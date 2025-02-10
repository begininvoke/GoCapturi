package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Move these functions here:
// - setupBrowserContext
// - listenNetworkEvents
// - autoScroll
// - navigateAndCapture
// - fetchRequestBody
// - processFinishedRequests

func processFinishedRequests(ctx context.Context, requests *map[network.RequestID]*reqResData, finished *[]network.RequestID, mu *sync.Mutex) []*reqResData {
	var dataList []*reqResData
	mu.Lock()
	finishedIDs := *finished
	mu.Unlock()

	for _, id := range finishedIDs {
		mu.Lock()
		data, exists := (*requests)[id]
		mu.Unlock()

		if !exists {
			continue
		}

		var buf []byte
		if !data.SkipBody {
			err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				buf, err = network.GetResponseBody(id).Do(ctx)
				return err
			}))
			if err != nil {
				log.Printf("Failed to fetch response body for %s: %v", data.URL, err)
			}
		}

		mu.Lock()
		data.ResponseBody = buf
		dataList = append(dataList, data)
		mu.Unlock()
	}

	sort.Slice(dataList, func(i, j int) bool {
		return dataList[i].SequenceID < dataList[j].SequenceID
	})

	return dataList
}
func fetchRequestBody(ctx context.Context, id network.RequestID, requests *map[network.RequestID]*reqResData, mu *sync.Mutex) {
	var body string
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		var err error
		body, err = network.GetRequestPostData(id).Do(ctx)
		return err
	}))

	if err != nil {
		//log.Printf("Failed to fetch request body: %v", err)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	if data, exists := (*requests)[id]; exists && !data.SkipBody {
		data.RequestBody = body
	}
}

func navigateAndCapture(ctx context.Context) error {
	return chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(*outputURL),
		chromedp.ActionFunc(autoScroll),
		chromedp.Sleep(*timeoutFlag),
	)
}
func autoScroll(ctx context.Context) error {
	const (
		scrollDelay = time.Second
		maxRetries  = 10
	)

	var (
		stableCount int
	)

	for stableCount < maxRetries {
		var currentHeight int64

		if err := chromedp.Evaluate(`document.documentElement.scrollHeight`, &currentHeight).Do(ctx); err != nil {
			return fmt.Errorf("failed to get scroll height: %w", err)
		}

		if err := chromedp.Evaluate(`window.scrollTo(0, document.documentElement.scrollHeight)`, nil).Do(ctx); err != nil {
			return fmt.Errorf("failed to scroll: %w", err)
		}

		time.Sleep(scrollDelay)

		if err := chromedp.Evaluate(`window.scrollTo({ top: 100, left: 100, behavior: 'smooth' });`, nil).Do(ctx); err != nil {
			return fmt.Errorf("failed to scroll: %w", err)
		}
		time.Sleep(scrollDelay)
		stableCount++

	}

	return nil
}

func setupBrowserContext() (context.Context, context.CancelFunc) {
	opts := chromedp.DefaultExecAllocatorOptions[:]

	ctx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel = chromedp.NewContext(ctx)
	ctx, cancel = context.WithTimeout(ctx, 90*time.Second)
	return ctx, cancel
}
func listenNetworkEvents(ctx context.Context, requests *map[network.RequestID]*reqResData, finished *[]network.RequestID, mu *sync.Mutex, seqID *int, excludeExts map[string]struct{}, ignoreExts map[string]struct{}) {
	chromedp.ListenTarget(ctx, func(v interface{}) {
		switch ev := v.(type) {
		case *network.EventRequestWillBeSent:
			requestDomain := extractDomain(ev.Request.URL)
			if *domainFlag != "" && !isDomainMatch(requestDomain, *domainFlag) {
				return
			}

			mu.Lock()
			defer mu.Unlock()
			if _, exists := ignoreExts[getExtension(ev.Request.URL)]; exists {
				return
			}
			if _, exists := (*requests)[ev.RequestID]; exists {
				return
			}

			ext := getExtension(ev.Request.URL)
			_, skipBody := excludeExts[ext]

			*seqID++
			reqData := &reqResData{
				SequenceID:     *seqID,
				Domain:         requestDomain,
				URL:            ev.Request.URL,
				Method:         ev.Request.Method,
				RequestHeaders: ev.Request.Headers,
				RequestTime:    time.Now(),
				SkipBody:       skipBody,
			}

			if ev.Request.HasPostData && !skipBody {
				go fetchRequestBody(ctx, ev.RequestID, requests, mu)
			}

			(*requests)[ev.RequestID] = reqData

		case *network.EventResponseReceived:
			mu.Lock()
			defer mu.Unlock()
			if data, exists := (*requests)[ev.RequestID]; exists {
				data.ResponseStatus = float64(ev.Response.Status)
				data.ResponseHeaders = ev.Response.Headers
				data.ResponseTime = time.Now()
				data.TimeDiff = data.ResponseTime.Sub(data.RequestTime).String()
			}

		case *network.EventLoadingFinished:
			mu.Lock()
			*finished = append(*finished, ev.RequestID)
			mu.Unlock()
		}
	})
}
