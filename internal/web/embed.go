package web

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	extensionast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"gwiki/internal/index"
)

const mapsAppShortLinkPrefix = "https://maps.app.goo.gl/"
const mapsAppShortLinkPrefixInsecure = "http://maps.app.goo.gl/"

var (
	mapsEmbedKind         = ast.NewNodeKind("MapsEmbed")
	mapsEmbedCoordsRegexp = regexp.MustCompile(`@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)`)
	mapsEmbedHTTPClient   = &http.Client{Timeout: 3 * time.Second}
	mapsEmbedCacheKind    = "maps"
	mapsEmbedContextKey   = parser.NewContextKey()
)

const (
	mapsEmbedSuccessTTL  = 90 * 24 * time.Hour
	mapsEmbedFailureTTL  = 10 * time.Minute
	mapsEmbedPendingTTL  = 15 * time.Second
	mapsEmbedSyncTimeout = 1200 * time.Millisecond
)

var embedCacheStore *index.Index

var mapsEmbedInFlight = newTTLCache(512)

var (
	collapsibleSectionKind       = ast.NewNodeKind("CollapsibleSection")
	collapsibleSectionContextKey = parser.NewContextKey()
)

var (
	youtubeEmbedKind       = ast.NewNodeKind("YouTubeEmbed")
	youtubeEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	youtubeEmbedCacheKind  = "youtube"
	youtubeEmbedContextKey = parser.NewContextKey()
)

const (
	youtubeEmbedSuccessTTL  = 7 * 24 * time.Hour
	youtubeEmbedFailureTTL  = 30 * time.Minute
	youtubeEmbedPendingTTL  = 20 * time.Second
	youtubeEmbedSyncTimeout = 1200 * time.Millisecond
)

var youtubeEmbedInFlight = newTTLCache(512)

var (
	tiktokEmbedKind       = ast.NewNodeKind("TikTokEmbed")
	tiktokEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	tiktokEmbedCacheKind  = "tiktok"
	tiktokEmbedContextKey = parser.NewContextKey()
)

const (
	tiktokEmbedSuccessTTL  = 7 * 24 * time.Hour
	tiktokEmbedFailureTTL  = 30 * time.Minute
	tiktokEmbedPendingTTL  = 20 * time.Second
	tiktokEmbedSyncTimeout = 1200 * time.Millisecond
)

var tiktokEmbedInFlight = newTTLCache(512)

var (
	instagramEmbedKind       = ast.NewNodeKind("InstagramEmbed")
	instagramEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	instagramEmbedCacheKind  = "instagram"
	instagramEmbedContextKey = parser.NewContextKey()
)

const (
	instagramEmbedSuccessTTL  = 7 * 24 * time.Hour
	instagramEmbedFailureTTL  = 30 * time.Minute
	instagramEmbedPendingTTL  = 20 * time.Second
	instagramEmbedSyncTimeout = 1200 * time.Millisecond
)

var instagramEmbedInFlight = newTTLCache(512)

var (
	chatgptEmbedKind       = ast.NewNodeKind("ChatGPTEmbed")
	chatgptEmbedHTTPClient = &http.Client{Timeout: 3 * time.Second}
	chatgptEmbedCacheKind  = "chatgpt"
	chatgptEmbedContextKey = parser.NewContextKey()
)

const (
	chatgptEmbedSuccessTTL  = 7 * 24 * time.Hour
	chatgptEmbedFailureTTL  = 30 * time.Minute
	chatgptEmbedPendingTTL  = 20 * time.Second
	chatgptEmbedSyncTimeout = 1200 * time.Millisecond
)

var chatgptEmbedInFlight = newTTLCache(512)

var (
	attachmentVideoEmbedKind       = ast.NewNodeKind("AttachmentVideoEmbed")
	attachmentVideoEmbedContextKey = parser.NewContextKey()
)

var (
	linkTitleCacheKind  = "link_title"
	linkTitleContextKey = parser.NewContextKey()
	linkTitleHTTPClient = &http.Client{Timeout: 3 * time.Second}
)

const (
	linkTitleSuccessTTL = 7 * 24 * time.Hour
	linkTitleFailureTTL = 24 * time.Hour
	linkTitlePendingTTL = 20 * time.Second
)

var linkTitleInFlight = newTTLCache(512)

var (
	whatsappLinkKind = ast.NewNodeKind("WhatsAppLink")
)

type mapsEmbedStatus int

const (
	mapsEmbedStatusPending mapsEmbedStatus = iota
	mapsEmbedStatusFound
	mapsEmbedStatusFailed
)

type youtubeEmbedStatus int

const (
	youtubeEmbedStatusPending youtubeEmbedStatus = iota
	youtubeEmbedStatusFound
	youtubeEmbedStatusFailed
)

type tiktokEmbedStatus int

const (
	tiktokEmbedStatusPending tiktokEmbedStatus = iota
	tiktokEmbedStatusFound
	tiktokEmbedStatusFailed
)

type instagramEmbedStatus int

const (
	instagramEmbedStatusPending instagramEmbedStatus = iota
	instagramEmbedStatusFound
	instagramEmbedStatusFailed
)

type chatgptEmbedStatus int

const (
	chatgptEmbedStatusPending chatgptEmbedStatus = iota
	chatgptEmbedStatusFound
	chatgptEmbedStatusFailed
)

type collapsibleSection struct {
	ast.BaseBlock
	Title  string
	LineNo int
	Open   bool
}

func (n *collapsibleSection) Kind() ast.NodeKind {
	return collapsibleSectionKind
}

func (n *collapsibleSection) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":  n.Title,
		"LineNo": strconv.Itoa(n.LineNo),
	}, nil)
}

type collapsibleSectionExtension struct{}

func (e *collapsibleSectionExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&collapsibleSectionTransformer{}, 105),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newCollapsibleSectionHTMLRenderer(), 480),
	))
}

type collapsibleSectionTransformer struct{}

func (t *collapsibleSectionTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	source := reader.Source()
	state := collapsibleSectionRenderState{}
	if value := pc.Get(collapsibleSectionContextKey); value != nil {
		if resolved, ok := value.(collapsibleSectionRenderState); ok {
			state = resolved
		}
	}
	for current := node.FirstChild(); current != nil; {
		next := current.NextSibling()
		heading, ok := current.(*ast.Heading)
		if !ok || heading.Level != 2 || heading.Parent() != node {
			current = next
			continue
		}
		title := headingPlainText(heading, source)
		if strings.TrimSpace(title) == "" {
			title = "Section"
		}
		lineNo := headingLineInfo(heading, source)
		open := true
		if lineNo > 0 && state.Collapsed != nil {
			if _, ok := state.Collapsed[lineNo]; ok {
				open = false
			}
		}
		section := &collapsibleSection{
			Title:  title,
			LineNo: lineNo,
			Open:   open,
		}
		node.ReplaceChild(node, current, section)
		for child := next; child != nil; {
			childNext := child.NextSibling()
			if h2, ok := child.(*ast.Heading); ok && h2.Level == 2 && h2.Parent() == node {
				break
			}
			node.RemoveChild(node, child)
			section.AppendChild(section, child)
			child = childNext
		}
		current = section.NextSibling()
	}
}

func headingPlainText(node *ast.Heading, source []byte) string {
	var b strings.Builder
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := n.(type) {
		case *ast.Text:
			b.Write(v.Segment.Value(source))
		case *ast.String:
			b.Write(v.Text(source))
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
}

func headingLineInfo(node *ast.Heading, source []byte) int {
	lines := node.Lines()
	if lines == nil || lines.Len() == 0 {
		return 0
	}
	segment := lines.At(0)
	if segment.Start < 0 || segment.Start > len(source) {
		return 0
	}
	lineStart := bytes.LastIndex(source[:segment.Start], []byte("\n")) + 1
	lineNo := bytes.Count(source[:lineStart], []byte("\n")) + 1
	return lineNo
}

type collapsibleSectionHTMLRenderer struct{}

func newCollapsibleSectionHTMLRenderer() renderer.NodeRenderer {
	return &collapsibleSectionHTMLRenderer{}
}

func (r *collapsibleSectionHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(collapsibleSectionKind, r.renderCollapsibleSection)
}

func (r *collapsibleSectionHTMLRenderer) renderCollapsibleSection(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if entering {
		section := node.(*collapsibleSection)
		title := html.EscapeString(section.Title)
		_, _ = w.WriteString(`<details class="note-section"`)
		if section.Open {
			_, _ = w.WriteString(` open`)
		}
		if section.LineNo > 0 {
			_, _ = w.WriteString(` data-line-no="`)
			_, _ = w.WriteString(strconv.Itoa(section.LineNo))
			_, _ = w.WriteString(`"`)
		}
		_, _ = w.WriteString(`>`)
		_, _ = w.WriteString(`<summary class="note-section__summary">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</summary>`)
		return ast.WalkContinue, nil
	}
	_, _ = w.WriteString(`</details>`)
	return ast.WalkContinue, nil
}

type attachmentVideoEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *attachmentVideoEmbed) Kind() ast.NodeKind {
	return attachmentVideoEmbedKind
}

func (n *attachmentVideoEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type mapsEmbed struct {
	ast.BaseBlock
	URL             string
	OriginalURL     string
	FallbackMessage string
}

func (n *mapsEmbed) Kind() ast.NodeKind {
	return mapsEmbedKind
}

func (n *mapsEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"URL":      n.URL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type mapsEmbedExtension struct{}

func (e *mapsEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&mapsEmbedTransformer{}, 110),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newMapsEmbedHTMLRenderer(), 500),
	))
}

type youtubeEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *youtubeEmbed) Kind() ast.NodeKind {
	return youtubeEmbedKind
}

func (n *youtubeEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type youtubeEmbedExtension struct{}

func (e *youtubeEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&youtubeEmbedTransformer{}, 115),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newYouTubeEmbedHTMLRenderer(), 510),
	))
}

type tiktokEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *tiktokEmbed) Kind() ast.NodeKind {
	return tiktokEmbedKind
}

func (n *tiktokEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type tiktokEmbedExtension struct{}

func (e *tiktokEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&tiktokEmbedTransformer{}, 120),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newTikTokEmbedHTMLRenderer(), 520),
	))
}

type instagramEmbed struct {
	ast.BaseBlock
	Title           string
	ThumbnailURL    string
	OriginalURL     string
	FallbackMessage string
}

func (n *instagramEmbed) Kind() ast.NodeKind {
	return instagramEmbedKind
}

func (n *instagramEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Thumb":    n.ThumbnailURL,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type instagramEmbedExtension struct{}

func (e *instagramEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&instagramEmbedTransformer{}, 125),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newInstagramEmbedHTMLRenderer(), 530),
	))
}

type chatgptEmbed struct {
	ast.BaseBlock
	Title           string
	Preview         string
	OriginalURL     string
	FallbackMessage string
}

func (n *chatgptEmbed) Kind() ast.NodeKind {
	return chatgptEmbedKind
}

func (n *chatgptEmbed) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Title":    n.Title,
		"Preview":  n.Preview,
		"Original": n.OriginalURL,
		"Fallback": n.FallbackMessage,
	}, nil)
}

type chatgptEmbedExtension struct{}

func (e *chatgptEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&chatgptEmbedTransformer{}, 128),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newChatGPTEmbedHTMLRenderer(), 535),
	))
}

type whatsappLink struct {
	ast.BaseInline
	Number      string
	OriginalURL string
}

func (n *whatsappLink) Kind() ast.NodeKind {
	return whatsappLinkKind
}

func (n *whatsappLink) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, map[string]string{
		"Number":   n.Number,
		"Original": n.OriginalURL,
	}, nil)
}

type whatsappLinkExtension struct{}

func (e *whatsappLinkExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&whatsappLinkTransformer{}, 129),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newWhatsAppLinkHTMLRenderer(), 536),
	))
}

type attachmentVideoEmbedExtension struct{}

func (e *attachmentVideoEmbedExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&attachmentVideoEmbedTransformer{}, 130),
	))
	m.Renderer().AddOptions(renderer.WithNodeRenderers(
		util.Prioritized(newAttachmentVideoEmbedHTMLRenderer(), 540),
	))
}

type linkTitleExtension struct{}

func (e *linkTitleExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(parser.WithASTTransformers(
		util.Prioritized(&linkTitleTransformer{}, 135),
	))
}

type linkTitleTransformer struct{}

func (t *linkTitleTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := linkTitleContext(pc)
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch link := n.(type) {
		case *ast.Link:
			urlText := strings.TrimSpace(string(link.Destination))
			if !isExternalHTTPURL(urlText) {
				return ast.WalkContinue, nil
			}
			label, ok := linkLabelText(link, source)
			if !ok || !textMatchesURL(label, urlText) {
				return ast.WalkContinue, nil
			}
			title, ok := lookupLinkTitle(ctx, urlText)
			if !ok || title == "" {
				return ast.WalkContinue, nil
			}
			replaceLinkLabel(link, title)
			if shouldOpenNewTab(link.Destination) {
				link.SetAttributeString("target", []byte("_blank"))
				link.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			urlText := strings.TrimSpace(string(link.URL(source)))
			if !isExternalHTTPURL(urlText) {
				return ast.WalkContinue, nil
			}
			title, ok := lookupLinkTitle(ctx, urlText)
			if !ok || title == "" {
				return ast.WalkContinue, nil
			}
			parent := link.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			newLink := ast.NewLink()
			newLink.Destination = []byte(urlText)
			newLink.AppendChild(newLink, ast.NewString([]byte(title)))
			if shouldOpenNewTab(newLink.Destination) {
				newLink.SetAttributeString("target", []byte("_blank"))
				newLink.SetAttributeString("rel", []byte("noopener noreferrer"))
			}
			parent.ReplaceChild(parent, link, newLink)
		}
		return ast.WalkContinue, nil
	})
}

type mapsEmbedTransformer struct{}

func (t *mapsEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := mapsEmbedContext(pc)
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var url string
		switch link := n.(type) {
		case *ast.Link:
			url = string(link.Destination)
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			url = string(link.URL(source))
		default:
			return ast.WalkContinue, nil
		}
		url = strings.TrimSpace(url)
		if !isMapsAppShortLink(url) {
			return ast.WalkContinue, nil
		}

		status, embedURL, errMsg := lookupMapsEmbed(ctx, url)
		switch status {
		case mapsEmbedStatusFound:
			embed := &mapsEmbed{URL: embedURL, OriginalURL: url}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				if paragraphHasOnlyLink(para, source, url) {
					grand.ReplaceChild(grand, para, embed)
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		case mapsEmbedStatusFailed:
			embed := &mapsEmbed{
				OriginalURL:     url,
				FallbackMessage: errMsg,
			}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				if paragraphHasOnlyLink(para, source, url) {
					grand.ReplaceChild(grand, para, embed)
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		default:
			embed := &mapsEmbed{
				OriginalURL:     url,
				FallbackMessage: "Map preview loading. Reload to display the embed.",
			}
			parent := n.Parent()
			if parent == nil {
				return ast.WalkContinue, nil
			}
			if para, ok := parent.(*ast.Paragraph); ok {
				grand := para.Parent()
				if grand == nil {
					return ast.WalkContinue, nil
				}
				if paragraphHasOnlyLink(para, source, url) {
					grand.ReplaceChild(grand, para, embed)
					return ast.WalkContinue, nil
				}
				grand.InsertAfter(grand, para, embed)
				return ast.WalkContinue, nil
			}

			grand := parent.Parent()
			if grand != nil {
				grand.InsertAfter(grand, parent, embed)
			}
			return ast.WalkContinue, nil
		}
		return ast.WalkContinue, nil
	})
}

type youtubeEmbedTransformer struct{}

func (t *youtubeEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := youtubeEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			// Skip paragraphs already replaced during link processing.
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isYouTubeURL(urlText) {
				continue
			}
			status, title, thumb, errMsg := lookupYouTubeEmbed(ctx, urlText)
			embed := &youtubeEmbed{
				Title:        title,
				ThumbnailURL: thumb,
				OriginalURL:  urlText,
			}
			switch status {
			case youtubeEmbedStatusFailed:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = errMsg
			case youtubeEmbedStatusPending:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = "YouTube preview loading. Reload to display the card."
			}
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isYouTubeURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
		status, title, thumb, errMsg := lookupYouTubeEmbed(ctx, urlText)
		embed := &youtubeEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case youtubeEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case youtubeEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "YouTube preview loading. Reload to display the card."
		}
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type tiktokEmbedTransformer struct{}

func (t *tiktokEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := tiktokEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isTikTokURL(urlText) {
				continue
			}
			status, title, thumb, errMsg := lookupTikTokEmbed(ctx, urlText)
			embed := &tiktokEmbed{
				Title:        title,
				ThumbnailURL: thumb,
				OriginalURL:  urlText,
			}
			switch status {
			case tiktokEmbedStatusFailed:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = errMsg
			case tiktokEmbedStatusPending:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = "TikTok preview loading. Reload to display the card."
			}
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isTikTokURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
		status, title, thumb, errMsg := lookupTikTokEmbed(ctx, urlText)
		embed := &tiktokEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case tiktokEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case tiktokEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "TikTok preview loading. Reload to display the card."
		}
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type instagramEmbedTransformer struct{}

func (t *instagramEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := instagramEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isInstagramURL(urlText) {
				continue
			}
			status, title, thumb, errMsg := lookupInstagramEmbed(ctx, urlText)
			embed := &instagramEmbed{
				Title:        title,
				ThumbnailURL: thumb,
				OriginalURL:  urlText,
			}
			switch status {
			case instagramEmbedStatusFailed:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = errMsg
			case instagramEmbedStatusPending:
				embed.Title = ""
				embed.ThumbnailURL = ""
				embed.FallbackMessage = "Instagram preview loading. Reload to display the card."
			}
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isInstagramURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
		status, title, thumb, errMsg := lookupInstagramEmbed(ctx, urlText)
		embed := &instagramEmbed{
			Title:        title,
			ThumbnailURL: thumb,
			OriginalURL:  urlText,
		}
		switch status {
		case instagramEmbedStatusFailed:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = errMsg
		case instagramEmbedStatusPending:
			embed.Title = ""
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "Instagram preview loading. Reload to display the card."
		}
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type chatgptEmbedTransformer struct{}

func (t *chatgptEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx := chatgptEmbedContext(pc)
	source := reader.Source()
	var blocks []ast.Node
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			blocks = append(blocks, para)
		}
		if block, ok := n.(*ast.TextBlock); ok {
			blocks = append(blocks, block)
		}
		return ast.WalkContinue, nil
	})

	for _, block := range blocks {
		if !isEmbedParagraphParent(block.Parent()) {
			continue
		}
		if urlText, ok := blockOnlyURL(block, source); ok {
			if !isChatGPTShareURL(urlText) {
				continue
			}
			status, title, preview, errMsg := lookupChatGPTEmbed(ctx, urlText)
			embed := &chatgptEmbed{
				Title:       title,
				Preview:     preview,
				OriginalURL: urlText,
			}
			switch status {
			case chatgptEmbedStatusFailed:
				embed.Title = ""
				embed.Preview = ""
				embed.FallbackMessage = errMsg
			case chatgptEmbedStatusPending:
				embed.Title = ""
				embed.Preview = ""
				embed.FallbackMessage = "ChatGPT preview loading. Reload to display the card."
			}
			parent := block.Parent()
			replaceBlockWithEmbed(parent, block, embed)
			continue
		}
		urlText, hasTextBefore, _, linkNode, ok := blockSingleLinkWithText(block, source)
		if !ok || !isChatGPTShareURL(urlText) {
			continue
		}
		block.RemoveChild(block, linkNode)
		status, title, preview, errMsg := lookupChatGPTEmbed(ctx, urlText)
		embed := &chatgptEmbed{
			Title:       title,
			Preview:     preview,
			OriginalURL: urlText,
		}
		switch status {
		case chatgptEmbedStatusFailed:
			embed.Title = ""
			embed.Preview = ""
			embed.FallbackMessage = errMsg
		case chatgptEmbedStatusPending:
			embed.Title = ""
			embed.Preview = ""
			embed.FallbackMessage = "ChatGPT preview loading. Reload to display the card."
		}
		parent := block.Parent()
		if parent == nil {
			continue
		}
		if hasTextBefore {
			parent.InsertAfter(parent, block, embed)
			continue
		}
		parent.ReplaceChild(parent, block, embed)
		parent.InsertAfter(parent, embed, block)
	}
}

type whatsappLinkTransformer struct{}

func (t *whatsappLinkTransformer) Transform(node *ast.Document, reader text.Reader, _ parser.Context) {
	source := reader.Source()
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		var urlText string
		switch link := n.(type) {
		case *ast.Link:
			urlText = strings.TrimSpace(string(link.Destination))
		case *ast.AutoLink:
			if link.AutoLinkType != ast.AutoLinkURL {
				return ast.WalkContinue, nil
			}
			urlText = strings.TrimSpace(string(link.URL(source)))
		default:
			return ast.WalkContinue, nil
		}
		number, ok := whatsAppNumber(urlText)
		if !ok {
			return ast.WalkContinue, nil
		}
		parent := n.Parent()
		if parent == nil {
			return ast.WalkContinue, nil
		}
		parent.ReplaceChild(parent, n, &whatsappLink{
			Number:      number,
			OriginalURL: urlText,
		})
		return ast.WalkContinue, nil
	})
}

type attachmentVideoEmbedTransformer struct{}

func (t *attachmentVideoEmbedTransformer) Transform(node *ast.Document, reader text.Reader, pc parser.Context) {
	ctx, srv := attachmentVideoEmbedContext(pc)
	if srv == nil {
		return
	}
	source := reader.Source()
	var paragraphs []*ast.Paragraph
	ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if para, ok := n.(*ast.Paragraph); ok {
			paragraphs = append(paragraphs, para)
		}
		return ast.WalkContinue, nil
	})

	for _, para := range paragraphs {
		if !isEmbedParagraphParent(para.Parent()) {
			continue
		}
		urlText, label, _, ok := paragraphOnlyMedia(para, source)
		if !ok {
			embeds := make([]ast.Node, 0, 2)
			remove := make([]ast.Node, 0, 2)
			for child := para.FirstChild(); child != nil; child = child.NextSibling() {
				inlineURL, inlineLabel, ok := inlineMediaURL(child, source)
				if !ok {
					continue
				}
				noteID, relPath, ok := attachmentVideoFromURL(inlineURL)
				if !ok {
					continue
				}
				thumbURL, ok := srv.ensureVideoThumbnail(ctx, noteID, relPath)
				title := strings.TrimSpace(inlineLabel)
				if title == "" {
					title = path.Base(relPath)
				}
				embed := &attachmentVideoEmbed{
					Title:        title,
					ThumbnailURL: thumbURL,
					OriginalURL:  inlineURL,
				}
				if !ok {
					embed.ThumbnailURL = ""
					embed.FallbackMessage = "Video preview unavailable."
				}
				embeds = append(embeds, embed)
				remove = append(remove, child)
			}
			if len(embeds) == 0 {
				continue
			}
			for _, node := range remove {
				para.RemoveChild(para, node)
			}
			parent := para.Parent()
			if parent == nil {
				continue
			}
			if !paragraphHasVisibleContent(para, source) {
				first := embeds[0]
				replaceBlockWithEmbed(parent, para, first)
				cursor := first
				for i := 1; i < len(embeds); i++ {
					parent.InsertAfter(parent, cursor, embeds[i])
					cursor = embeds[i]
				}
				continue
			}
			cursor := ast.Node(para)
			for _, embed := range embeds {
				parent.InsertAfter(parent, cursor, embed)
				cursor = embed
			}
			continue
		}
		noteID, relPath, ok := attachmentVideoFromURL(urlText)
		if !ok {
			continue
		}
		thumbURL, ok := srv.ensureVideoThumbnail(ctx, noteID, relPath)
		title := strings.TrimSpace(label)
		if title == "" {
			title = path.Base(relPath)
		}
		embed := &attachmentVideoEmbed{
			Title:        title,
			ThumbnailURL: thumbURL,
			OriginalURL:  urlText,
		}
		if !ok {
			embed.ThumbnailURL = ""
			embed.FallbackMessage = "Video preview unavailable."
		}
		parent := para.Parent()
		replaceBlockWithEmbed(parent, para, embed)
	}
}

func replaceBlockWithEmbed(parent ast.Node, block ast.Node, embed ast.Node) {
	if parent == nil {
		return
	}
	if checkbox := taskCheckboxClone(block); checkbox != nil {
		placeholder := ast.NewParagraph()
		placeholder.AppendChild(placeholder, checkbox)
		parent.ReplaceChild(parent, block, placeholder)
		parent.InsertAfter(parent, placeholder, embed)
		return
	}
	parent.ReplaceChild(parent, block, embed)
}

func taskCheckboxClone(block ast.Node) *extensionast.TaskCheckBox {
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		if checkbox, ok := child.(*extensionast.TaskCheckBox); ok {
			return extensionast.NewTaskCheckBox(checkbox.IsChecked)
		}
	}
	return nil
}

func blockHasTaskCheckbox(block ast.Node) bool {
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		if _, ok := child.(*extensionast.TaskCheckBox); ok {
			return true
		}
	}
	return false
}

func isTaskMarkerText(text string) bool {
	switch strings.TrimSpace(text) {
	case "[ ]", "[x]", "[X]":
		return true
	default:
		return false
	}
}

func paragraphHasOnlyLink(para *ast.Paragraph, source []byte, rawURL string) bool {
	rawURL = strings.TrimSpace(strings.Trim(rawURL, "<>"))
	linkCount := 0
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			linkCount++
			if linkCount > 1 {
				return false
			}
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
				return false
			}
			linkURL := strings.TrimSpace(string(node.Destination))
			if rawURL != "" && !textMatchesURL(linkURL, rawURL) {
				return false
			}
		case *ast.AutoLink:
			linkCount++
			if linkCount > 1 {
				return false
			}
			linkURL := strings.TrimSpace(string(node.URL(source)))
			if rawURL != "" && !textMatchesURL(linkURL, rawURL) {
				return false
			}
		case *ast.Text:
			text := strings.TrimSpace(strings.Trim(string(node.Segment.Value(source)), "<>"))
			if text == "" {
				continue
			}
			if rawURL != "" && textMatchesURL(text, rawURL) {
				continue
			}
			return false
		default:
			return false
		}
	}
	return linkCount == 1
}

func textMatchesURL(text string, rawURL string) bool {
	trimmed := strings.TrimSpace(text)
	rawURL = strings.TrimSpace(rawURL)
	if strings.EqualFold(trimmed, rawURL) {
		return true
	}
	if strings.EqualFold(strings.TrimSuffix(trimmed, "/"), strings.TrimSuffix(rawURL, "/")) {
		return true
	}
	trimmed = strings.Trim(trimmed, ".,)")
	if strings.EqualFold(trimmed, rawURL) {
		return true
	}
	return false
}

func linkLabelText(link *ast.Link, source []byte) (string, bool) {
	var b strings.Builder
	for child := link.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Text:
			b.Write(node.Segment.Value(source))
		case *ast.String:
			b.Write(node.Value)
		default:
			return "", false
		}
	}
	text := strings.TrimSpace(b.String())
	if text == "" {
		return "", false
	}
	return text, true
}

func replaceLinkLabel(link *ast.Link, title string) {
	for child := link.FirstChild(); child != nil; {
		next := child.NextSibling()
		link.RemoveChild(link, child)
		child = next
	}
	link.AppendChild(link, ast.NewString([]byte(title)))
}

func isExternalHTTPURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

func isIPHost(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

func isIgnoredLinkTitle(title string) bool {
	lower := strings.ToLower(strings.TrimSpace(title))
	if lower == "" {
		return true
	}
	return strings.HasPrefix(lower, "login") ||
		strings.HasPrefix(lower, "sign in") ||
		strings.HasPrefix(lower, "sign-in")
}

var metaTagRegexp = regexp.MustCompile(`(?is)<meta\s+[^>]*>`)
var metaAttrRegexp = regexp.MustCompile(`(?i)([a-zA-Z:-]+)\s*=\s*["']([^"']+)["']`)
var titleTagRegexp = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractMetaContent(htmlStr string, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return ""
	}
	for _, tag := range metaTagRegexp.FindAllString(htmlStr, -1) {
		var name string
		var content string
		for _, match := range metaAttrRegexp.FindAllStringSubmatch(tag, -1) {
			if len(match) != 3 {
				continue
			}
			attrName := strings.ToLower(strings.TrimSpace(match[1]))
			attrValue := strings.TrimSpace(match[2])
			switch attrName {
			case "property", "name":
				name = strings.ToLower(attrValue)
			case "content":
				content = attrValue
			}
		}
		if name == key && content != "" {
			return html.UnescapeString(content)
		}
	}
	return ""
}

func extractTitleTag(htmlStr string) string {
	match := titleTagRegexp.FindStringSubmatch(htmlStr)
	if len(match) < 2 {
		return ""
	}
	return html.UnescapeString(strings.TrimSpace(match[1]))
}

func isEmbedParagraphParent(parent ast.Node) bool {
	switch parent.(type) {
	case *ast.Document, *ast.ListItem:
		return true
	default:
		return false
	}
}

func blockOnlyURL(block ast.Node, source []byte) (string, bool) {
	hasTask := blockHasTaskCheckbox(block)
	var b strings.Builder
	hasLink := false
	hasURLText := false
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *extensionast.TaskCheckBox:
			continue
		case *ast.Link:
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
				return "", false
			}
			if hasLink || hasURLText {
				return "", false
			}
			hasLink = true
			b.Reset()
			b.WriteString(strings.TrimSpace(string(node.Destination)))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", false
			}
			if hasLink || hasURLText {
				return "", false
			}
			hasLink = true
			b.Reset()
			b.WriteString(strings.TrimSpace(string(node.URL(source))))
		case *ast.Text:
			text := strings.TrimSpace(string(node.Segment.Value(source)))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if hasLink {
				if textMatchesURL(text, b.String()) {
					continue
				}
				return "", false
			}
			if !linkifyURLRegexp.MatchString(text) {
				return "", false
			}
			if hasURLText {
				return "", false
			}
			hasURLText = true
			b.Reset()
			b.WriteString(text)
		case *ast.String:
			text := strings.TrimSpace(string(node.Value))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if hasLink {
				if textMatchesURL(text, b.String()) {
					continue
				}
				return "", false
			}
			if !linkifyURLRegexp.MatchString(text) {
				return "", false
			}
			if hasURLText {
				return "", false
			}
			hasURLText = true
			b.Reset()
			b.WriteString(text)
		default:
			return "", false
		}
	}
	value := strings.TrimSpace(string(b.String()))
	if value == "" || (!hasLink && !hasURLText) {
		return "", false
	}
	return strings.Trim(value, "<>"), true
}

func blockSingleLinkWithText(block ast.Node, source []byte) (string, bool, bool, ast.Node, bool) {
	hasTask := blockHasTaskCheckbox(block)
	var (
		foundLink     bool
		urlText       string
		linkNode      ast.Node
		hasTextBefore bool
		hasTextAfter  bool
	)
	for child := block.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *extensionast.TaskCheckBox:
			continue
		case *ast.Link:
			if foundLink {
				return "", false, false, nil, false
			}
			if label, ok := linkLabelText(node, source); ok && strings.TrimSpace(label) != "" {
				return "", false, false, nil, false
			}
			foundLink = true
			urlText = strings.TrimSpace(string(node.Destination))
			linkNode = node
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", false, false, nil, false
			}
			if foundLink {
				return "", false, false, nil, false
			}
			foundLink = true
			urlText = strings.TrimSpace(string(node.URL(source)))
			linkNode = node
		case *ast.Text:
			text := strings.TrimSpace(string(node.Segment.Value(source)))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if !foundLink {
				hasTextBefore = true
				continue
			}
			hasTextAfter = true
		case *ast.String:
			text := strings.TrimSpace(string(node.Value))
			if text == "" {
				continue
			}
			if hasTask && isTaskMarkerText(text) {
				continue
			}
			if !foundLink {
				hasTextBefore = true
				continue
			}
			hasTextAfter = true
		default:
			return "", false, false, nil, false
		}
	}
	if !foundLink || strings.TrimSpace(urlText) == "" || (!hasTextBefore && !hasTextAfter) {
		return "", false, false, nil, false
	}
	return strings.Trim(urlText, "<>"), hasTextBefore, hasTextAfter, linkNode, true
}

func paragraphOnlyLink(para *ast.Paragraph, source []byte) (string, string, bool) {
	var (
		foundLink ast.Node
		urlText   string
	)
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			if foundLink != nil {
				return "", "", false
			}
			foundLink = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", "", false
			}
			if foundLink != nil {
				return "", "", false
			}
			foundLink = node
			urlText = strings.TrimSpace(string(node.URL(source)))
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) == "" {
				continue
			}
			return "", "", false
		default:
			return "", "", false
		}
	}
	if foundLink == nil || urlText == "" {
		return "", "", false
	}
	label := ""
	if linkNode, ok := foundLink.(*ast.Link); ok {
		label = extractTextFromNode(linkNode, source)
	} else {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, true
}

func paragraphOnlyMedia(para *ast.Paragraph, source []byte) (string, string, ast.Node, bool) {
	var (
		foundNode ast.Node
		urlText   string
	)
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Link:
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.AutoLink:
			if node.AutoLinkType != ast.AutoLinkURL {
				return "", "", nil, false
			}
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.URL(source)))
		case *ast.Image:
			if foundNode != nil {
				return "", "", nil, false
			}
			foundNode = node
			urlText = strings.TrimSpace(string(node.Destination))
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) == "" {
				continue
			}
			return "", "", nil, false
		default:
			return "", "", nil, false
		}
	}
	if foundNode == nil || urlText == "" {
		return "", "", nil, false
	}
	label := ""
	switch node := foundNode.(type) {
	case *ast.Link:
		label = extractTextFromNode(node, source)
	case *ast.Image:
		label = extractTextFromNode(node, source)
		if label == "" {
			label = strings.TrimSpace(string(node.Title))
		}
	}
	if label == "" {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, foundNode, true
}

func inlineMediaURL(node ast.Node, source []byte) (string, string, bool) {
	var (
		urlText string
		label   string
	)
	switch typed := node.(type) {
	case *ast.Link:
		urlText = strings.TrimSpace(string(typed.Destination))
		label = extractTextFromNode(typed, source)
	case *ast.AutoLink:
		if typed.AutoLinkType != ast.AutoLinkURL {
			return "", "", false
		}
		urlText = strings.TrimSpace(string(typed.URL(source)))
		label = urlText
	case *ast.Image:
		urlText = strings.TrimSpace(string(typed.Destination))
		label = extractTextFromNode(typed, source)
		if label == "" {
			label = strings.TrimSpace(string(typed.Title))
		}
	default:
		return "", "", false
	}
	if urlText == "" {
		return "", "", false
	}
	if label == "" {
		label = urlText
	}
	return strings.Trim(urlText, "<>"), label, true
}

func paragraphHasVisibleContent(para *ast.Paragraph, source []byte) bool {
	for child := para.FirstChild(); child != nil; child = child.NextSibling() {
		switch node := child.(type) {
		case *ast.Text:
			if strings.TrimSpace(string(node.Segment.Value(source))) != "" {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func extractTextFromNode(node ast.Node, source []byte) string {
	var b strings.Builder
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if textNode, ok := n.(*ast.Text); ok {
			b.Write(textNode.Segment.Value(source))
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(b.String())
}

type mapsEmbedHTMLRenderer struct{}

func newMapsEmbedHTMLRenderer() renderer.NodeRenderer {
	return &mapsEmbedHTMLRenderer{}
}

func (r *mapsEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(mapsEmbedKind, r.renderMapsEmbed)
}

func (r *mapsEmbedHTMLRenderer) renderMapsEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*mapsEmbed)
	if n.URL != "" {
		escapedURL := html.EscapeString(n.URL)
		_, _ = w.WriteString(`<div class="map-card">`)
		_, _ = w.WriteString(`<div class="map-card__meta">`)
		_, _ = w.WriteString(`<div class="map-card__title">Map preview</div>`)
		_, _ = w.WriteString(`<div class="map-card__host">google.com/maps</div>`)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="map-card__embed">`)
		_, _ = w.WriteString(`<iframe src="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" loading="lazy" referrerpolicy="no-referrer-when-downgrade"`)
		_, _ = w.WriteString(` style="border:0;" width="100%" height="360" allowfullscreen></iframe>`)
		_, _ = w.WriteString(`</div></div>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="map-embed map-embed-fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open in Google Maps</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type youtubeEmbedHTMLRenderer struct{}

func newYouTubeEmbedHTMLRenderer() renderer.NodeRenderer {
	return &youtubeEmbedHTMLRenderer{}
}

func (r *youtubeEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(youtubeEmbedKind, r.renderYouTubeEmbed)
}

func (r *youtubeEmbedHTMLRenderer) renderYouTubeEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*youtubeEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="youtube-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="youtube-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="youtube-card__meta">`)
		_, _ = w.WriteString(`<div class="youtube-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="youtube-card__host">youtube.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="youtube-card youtube-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on YouTube</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type tiktokEmbedHTMLRenderer struct{}

func newTikTokEmbedHTMLRenderer() renderer.NodeRenderer {
	return &tiktokEmbedHTMLRenderer{}
}

func (r *tiktokEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(tiktokEmbedKind, r.renderTikTokEmbed)
}

func (r *tiktokEmbedHTMLRenderer) renderTikTokEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*tiktokEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="tiktok-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="tiktok-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="tiktok-card__meta">`)
		_, _ = w.WriteString(`<div class="tiktok-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="tiktok-card__host">tiktok.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="tiktok-card tiktok-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on TikTok</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type instagramEmbedHTMLRenderer struct{}

func newInstagramEmbedHTMLRenderer() renderer.NodeRenderer {
	return &instagramEmbedHTMLRenderer{}
}

func (r *instagramEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(instagramEmbedKind, r.renderInstagramEmbed)
}

func (r *instagramEmbedHTMLRenderer) renderInstagramEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*instagramEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="instagram-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="instagram-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="instagram-card__meta">`)
		_, _ = w.WriteString(`<div class="instagram-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="instagram-card__host">instagram.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="instagram-card instagram-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on Instagram</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type chatgptEmbedHTMLRenderer struct{}

func newChatGPTEmbedHTMLRenderer() renderer.NodeRenderer {
	return &chatgptEmbedHTMLRenderer{}
}

func (r *chatgptEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(chatgptEmbedKind, r.renderChatGPTEmbed)
}

func (r *chatgptEmbedHTMLRenderer) renderChatGPTEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*chatgptEmbed)
	if n.OriginalURL != "" && n.Title != "" {
		title := html.EscapeString(n.Title)
		preview := html.EscapeString(n.Preview)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="chatgpt-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="chatgpt-card__meta">`)
		_, _ = w.WriteString(`<div class="chatgpt-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		if preview != "" {
			_, _ = w.WriteString(`<div class="chatgpt-card__preview">`)
			_, _ = w.WriteString(preview)
			_, _ = w.WriteString(`</div>`)
		}
		_, _ = w.WriteString(`<div class="chatgpt-card__host">chatgpt.com</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="chatgpt-card chatgpt-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open on ChatGPT</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

type whatsappLinkHTMLRenderer struct{}

func newWhatsAppLinkHTMLRenderer() renderer.NodeRenderer {
	return &whatsappLinkHTMLRenderer{}
}

func (r *whatsappLinkHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(whatsappLinkKind, r.renderWhatsAppLink)
}

func (r *whatsappLinkHTMLRenderer) renderWhatsAppLink(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*whatsappLink)
	if n.OriginalURL == "" || n.Number == "" {
		return ast.WalkContinue, nil
	}
	url := html.EscapeString(n.OriginalURL)
	number := html.EscapeString(n.Number)
	_, _ = w.WriteString(`<a class="whatsapp-link" href="`)
	_, _ = w.WriteString(url)
	_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
	_, _ = w.WriteString(`<span class="whatsapp-link__icon" aria-hidden="true">`)
	_, _ = w.WriteString(`<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6">`)
	_, _ = w.WriteString(`<path d="M20.3 12.1c0 4.5-3.7 8.2-8.2 8.2-1.4 0-2.7-.4-3.9-1l-4.5 1.2 1.2-4.4c-.7-1.2-1.1-2.6-1.1-4 0-4.5 3.7-8.2 8.2-8.2 4.5 0 8.3 3.7 8.3 8.2z"/>`)
	_, _ = w.WriteString(`<path d="M9.3 7.7c-.2-.4-.4-.4-.6-.4h-.6c-.2 0-.5.1-.7.4-.3.3-.9.9-.9 2.2 0 1.3 1 2.5 1.1 2.7.1.2 2 3.1 4.9 4.2 2.4.9 2.9.7 3.4.7.5-.1 1.6-.7 1.8-1.3.2-.6.2-1.1.1-1.3-.1-.2-.3-.3-.7-.5-.4-.2-2.2-1.1-2.6-1.2-.3-.1-.6-.2-.8.2-.2.3-.9 1.2-1.1 1.4-.2.2-.4.3-.8.1-.4-.2-1.7-.6-3.2-1.9-1.2-1-2-2.2-2.2-2.6-.2-.4 0-.6.1-.8.2-.2.4-.4.6-.6.2-.2.3-.4.4-.6.1-.2 0-.4 0-.6-.1-.2-.7-1.9-1-2.5z"/>`)
	_, _ = w.WriteString(`</svg></span>`)
	_, _ = w.WriteString(`<span class="whatsapp-link__number">`)
	_, _ = w.WriteString(number)
	_, _ = w.WriteString(`</span></a>`)
	return ast.WalkContinue, nil
}

type attachmentVideoEmbedHTMLRenderer struct{}

func newAttachmentVideoEmbedHTMLRenderer() renderer.NodeRenderer {
	return &attachmentVideoEmbedHTMLRenderer{}
}

func (r *attachmentVideoEmbedHTMLRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(attachmentVideoEmbedKind, r.renderAttachmentVideoEmbed)
}

func (r *attachmentVideoEmbedHTMLRenderer) renderAttachmentVideoEmbed(
	w util.BufWriter, source []byte, node ast.Node, entering bool,
) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	n := node.(*attachmentVideoEmbed)
	if n.ThumbnailURL != "" && n.OriginalURL != "" {
		thumb := html.EscapeString(n.ThumbnailURL)
		title := html.EscapeString(n.Title)
		url := html.EscapeString(n.OriginalURL)
		_, _ = w.WriteString(`<a class="video-card" href="`)
		_, _ = w.WriteString(url)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">`)
		_, _ = w.WriteString(`<div class="video-card__thumb"><img src="`)
		_, _ = w.WriteString(thumb)
		_, _ = w.WriteString(`" alt="`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`"></div>`)
		_, _ = w.WriteString(`<div class="video-card__meta">`)
		_, _ = w.WriteString(`<div class="video-card__title">`)
		_, _ = w.WriteString(title)
		_, _ = w.WriteString(`</div>`)
		_, _ = w.WriteString(`<div class="video-card__host">mp4</div>`)
		_, _ = w.WriteString(`</div></a>`)
		return ast.WalkContinue, nil
	}
	if n.FallbackMessage != "" && n.OriginalURL != "" {
		escapedURL := html.EscapeString(n.OriginalURL)
		escapedMsg := html.EscapeString(n.FallbackMessage)
		_, _ = w.WriteString(`<div class="video-card video-card--fallback">`)
		_, _ = w.WriteString(`<span>`)
		_, _ = w.WriteString(escapedMsg)
		_, _ = w.WriteString(`</span> `)
		_, _ = w.WriteString(`<a href="`)
		_, _ = w.WriteString(escapedURL)
		_, _ = w.WriteString(`" target="_blank" rel="noopener noreferrer">Open video</a>`)
		_, _ = w.WriteString(`</div>`)
	}
	return ast.WalkContinue, nil
}

func isMapsAppShortLink(url string) bool {
	lower := strings.ToLower(strings.TrimSpace(url))
	return strings.HasPrefix(lower, mapsAppShortLinkPrefix) ||
		strings.HasPrefix(lower, mapsAppShortLinkPrefixInsecure)
}

func mapsEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(mapsEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func youtubeEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(youtubeEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func tiktokEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(tiktokEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func instagramEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(instagramEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func chatgptEmbedContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(chatgptEmbedContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

type attachmentVideoEmbedContextValue struct {
	ctx    context.Context
	server *Server
}

func attachmentVideoEmbedContext(pc parser.Context) (context.Context, *Server) {
	if pc == nil {
		return context.Background(), nil
	}
	if value := pc.Get(attachmentVideoEmbedContextKey); value != nil {
		if ctxValue, ok := value.(attachmentVideoEmbedContextValue); ok {
			if ctxValue.ctx == nil {
				ctxValue.ctx = context.Background()
			}
			return ctxValue.ctx, ctxValue.server
		}
	}
	return context.Background(), nil
}

func linkTitleContext(pc parser.Context) context.Context {
	if pc == nil {
		return context.Background()
	}
	if value := pc.Get(linkTitleContextKey); value != nil {
		if ctx, ok := value.(context.Context); ok && ctx != nil {
			return ctx
		}
	}
	return context.Background()
}

func isYouTubeURL(raw string) bool {
	_, ok := youtubeVideoID(raw)
	return ok
}

func isTikTokURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host == "tiktok.com" || host == "m.tiktok.com" {
		return true
	}
	if host == "vt.tiktok.com" || host == "vm.tiktok.com" {
		return true
	}
	return false
}

func isInstagramURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host != "instagram.com" && host != "m.instagram.com" {
		return false
	}
	pathValue := strings.TrimSpace(strings.Trim(parsed.Path, "/"))
	return pathValue != ""
}

func isChatGPTShareURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host != "chatgpt.com" {
		return false
	}
	return strings.HasPrefix(parsed.Path, "/s/")
}

func whatsAppNumber(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	switch host {
	case "wa.me":
		number := strings.TrimSpace(strings.Trim(parsed.Path, "/"))
		if number == "" {
			return "", false
		}
		return formatWhatsAppNumber(number), true
	case "api.whatsapp.com", "chat.whatsapp.com":
		phone := strings.TrimSpace(parsed.Query().Get("phone"))
		if phone == "" {
			return "", false
		}
		return formatWhatsAppNumber(phone), true
	}
	if strings.EqualFold(parsed.Scheme, "whatsapp") {
		phone := strings.TrimSpace(parsed.Query().Get("phone"))
		if phone == "" {
			phone = strings.TrimSpace(parsed.Query().Get("number"))
		}
		if phone == "" {
			return "", false
		}
		return formatWhatsAppNumber(phone), true
	}
	return "", false
}

func formatWhatsAppNumber(raw string) string {
	var digits strings.Builder
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
		}
	}
	value := digits.String()
	if value == "" {
		return raw
	}
	trimmed := strings.TrimSpace(raw)
	hasPlus := strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "00")
	if strings.HasPrefix(value, "0") {
		value = "62" + strings.TrimPrefix(value, "0")
	}
	country := "62"
	local := value
	if hasPlus {
		switch {
		case strings.HasPrefix(value, "1"):
			country = "1"
			local = strings.TrimPrefix(value, "1")
		case strings.HasPrefix(value, "7"):
			country = "7"
			local = strings.TrimPrefix(value, "7")
		case strings.HasPrefix(value, "62"):
			country = "62"
			local = strings.TrimPrefix(value, "62")
		default:
			for i := 1; i <= 3 && i <= len(value); i++ {
				country = value[:i]
				local = value[i:]
			}
		}
	} else if strings.HasPrefix(value, "62") {
		country = "62"
		local = strings.TrimPrefix(value, "62")
	} else if strings.HasPrefix(value, "1") || strings.HasPrefix(value, "7") {
		country = value[:1]
		local = value[1:]
	}
	if local == "" {
		return "+" + country
	}
	return formatIntlNumber(country, local)
}

func formatIntlNumber(country string, local string) string {
	group := local
	if len(local) > 3 {
		group = local[:3] + "-" + local[3:]
	}
	return "+" + country + " " + group
}

func attachmentVideoFromURL(raw string) (string, string, bool) {
	noteID, relPath, ok := attachmentFileFromURL(raw)
	if !ok {
		return "", "", false
	}
	if !isVideoExtension(relPath) {
		return "", "", false
	}
	return noteID, relPath, true
}

func isVideoExtension(relPath string) bool {
	ext := strings.ToLower(path.Ext(relPath))
	if ext == "" {
		return false
	}
	if ext == ".mp4" || ext == ".webm" || ext == ".mov" || ext == ".m4v" || ext == ".mkv" || ext == ".avi" {
		return true
	}
	mimeType := mime.TypeByExtension(ext)
	return strings.HasPrefix(mimeType, "video/")
}

func youtubeVideoID(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", false
	}
	host := strings.ToLower(parsed.Host)
	host = strings.TrimPrefix(host, "www.")
	if host == "youtu.be" {
		id := strings.Trim(parsed.Path, "/")
		if id == "" {
			return "", false
		}
		return id, true
	}
	if host == "youtube.com" || host == "m.youtube.com" {
		if strings.HasPrefix(parsed.Path, "/watch") {
			if id := parsed.Query().Get("v"); id != "" {
				return id, true
			}
		}
	}
	return "", false
}

func lookupTikTokEmbed(ctx context.Context, rawURL string) (tiktokEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, tiktokEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return tiktokEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "TikTok preview unavailable."
				}
				return tiktokEmbedStatusFailed, "", "", message
			}
		}
	}

	if tiktokEmbedIsInFlight(rawURL) {
		return tiktokEmbedStatusPending, "", "", ""
	}
	tiktokEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveTikTokEmbedNow(rawURL, tiktokEmbedSyncTimeout); ok {
		tiktokEmbedStoreFound(ctx, rawURL, title, thumb)
		tiktokEmbedClearInFlight(rawURL)
		return tiktokEmbedStatusFound, title, thumb, ""
	}

	go resolveTikTokEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return tiktokEmbedStatusPending, "", "", ""
}

func lookupInstagramEmbed(ctx context.Context, rawURL string) (instagramEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, instagramEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return instagramEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "Instagram preview unavailable."
				}
				return instagramEmbedStatusFailed, "", "", message
			}
		}
	}

	if instagramEmbedIsInFlight(rawURL) {
		return instagramEmbedStatusPending, "", "", ""
	}
	instagramEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveInstagramEmbedNow(rawURL, instagramEmbedSyncTimeout); ok {
		instagramEmbedStoreFound(ctx, rawURL, title, thumb)
		instagramEmbedClearInFlight(rawURL)
		return instagramEmbedStatusFound, title, thumb, ""
	}

	go resolveInstagramEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return instagramEmbedStatusPending, "", "", ""
}

func lookupChatGPTEmbed(ctx context.Context, rawURL string) (chatgptEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, chatgptEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return chatgptEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "ChatGPT preview unavailable."
				}
				return chatgptEmbedStatusFailed, "", "", message
			}
		}
	}

	if chatgptEmbedIsInFlight(rawURL) {
		return chatgptEmbedStatusPending, "", "", ""
	}
	chatgptEmbedMarkInFlight(rawURL)

	if title, preview, ok := resolveChatGPTEmbedNow(rawURL, chatgptEmbedSyncTimeout); ok {
		chatgptEmbedStoreFound(ctx, rawURL, title, preview)
		chatgptEmbedClearInFlight(rawURL)
		return chatgptEmbedStatusFound, title, preview, ""
	}

	go resolveChatGPTEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return chatgptEmbedStatusPending, "", "", ""
}

func lookupLinkTitle(ctx context.Context, rawURL string) (string, bool) {
	if isIPHost(rawURL) {
		return "", false
	}
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, linkTitleCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				title := strings.TrimSpace(entry.EmbedURL)
				if title != "" {
					return title, true
				}
			}
			return "", false
		}
		if err != nil {
			slog.Debug("link title cache lookup failed", "url", rawURL, "err", err)
		}
	}

	if embedCacheStore == nil || linkTitleIsInFlight(rawURL) {
		return "", false
	}
	linkTitleMarkInFlight(rawURL)
	slog.Debug("link title fetch queued", "url", rawURL)
	go resolveLinkTitleAsync(context.WithoutCancel(ctx), rawURL)
	return "", false
}

func linkTitleIsInFlight(rawURL string) bool {
	return linkTitleInFlight.IsActive(rawURL, time.Now())
}

func linkTitleMarkInFlight(rawURL string) {
	linkTitleInFlight.Upsert(rawURL, time.Now().Add(linkTitlePendingTTL))
}

func linkTitleClearInFlight(rawURL string) {
	linkTitleInFlight.Delete(rawURL)
}

func resolveLinkTitleAsync(ctx context.Context, rawURL string) {
	title, ok := resolveLinkTitleWithClient(rawURL, linkTitleHTTPClient)
	if !ok {
		linkTitleStoreFailure(ctx, rawURL, "Link title unavailable.")
		linkTitleClearInFlight(rawURL)
		return
	}

	linkTitleStoreFound(ctx, rawURL, title)
	linkTitleClearInFlight(rawURL)
}

func resolveLinkTitleWithClient(rawURL string, client *http.Client) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", false
	}
	htmlStr := string(body)
	title := extractMetaContent(htmlStr, "og:title")
	if title == "" {
		title = extractTitleTag(htmlStr)
	}
	title = strings.TrimSpace(title)
	if title == "" || isIgnoredLinkTitle(title) {
		return "", false
	}
	return title, true
}

func linkTitleStoreFound(ctx context.Context, rawURL string, title string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      linkTitleCacheKind,
		EmbedURL:  title,
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(linkTitleSuccessTTL),
	}
	if err := embedCacheStore.UpsertEmbedCache(ctx, entry); err != nil {
		slog.Debug("link title cache store failed", "url", rawURL, "err", err)
		return
	}
	if touched, err := embedCacheStore.TouchNotesByLink(context.WithoutCancel(ctx), rawURL); err != nil {
		slog.Debug("link title cache touch failed", "url", rawURL, "err", err)
	} else if touched > 0 {
		slog.Debug("link title cache touch", "url", rawURL, "notes", touched)
	}
	slog.Debug("link title cached", "url", rawURL)
}

func linkTitleStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      linkTitleCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(linkTitleFailureTTL),
	}
	if err := embedCacheStore.UpsertEmbedCache(ctx, entry); err != nil {
		slog.Debug("link title cache store failed", "url", rawURL, "err", err)
		return
	}
	if touched, err := embedCacheStore.TouchNotesByLink(context.WithoutCancel(ctx), rawURL); err != nil {
		slog.Debug("link title cache touch failed", "url", rawURL, "err", err)
	} else if touched > 0 {
		slog.Debug("link title cache touch", "url", rawURL, "notes", touched)
	}
	slog.Debug("link title cache failed", "url", rawURL, "err", message)
}

func lookupYouTubeEmbed(ctx context.Context, rawURL string) (youtubeEmbedStatus, string, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, rawURL, youtubeEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return youtubeEmbedStatusFound, entry.ErrorMsg, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "YouTube preview unavailable."
				}
				return youtubeEmbedStatusFailed, "", "", message
			}
		}
	}

	if youtubeEmbedIsInFlight(rawURL) {
		return youtubeEmbedStatusPending, "", "", ""
	}
	youtubeEmbedMarkInFlight(rawURL)

	if title, thumb, ok := resolveYouTubeEmbedNow(rawURL, youtubeEmbedSyncTimeout); ok {
		youtubeEmbedStoreFound(ctx, rawURL, title, thumb)
		youtubeEmbedClearInFlight(rawURL)
		return youtubeEmbedStatusFound, title, thumb, ""
	}

	go resolveYouTubeEmbedAsync(context.WithoutCancel(ctx), rawURL)
	return youtubeEmbedStatusPending, "", "", ""
}

func resolveTikTokEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveTikTokEmbedWithClient(rawURL, client)
}

func resolveTikTokEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveTikTokEmbedWithClient(rawURL, tiktokEmbedHTTPClient)
	if !ok {
		tiktokEmbedStoreFailure(ctx, rawURL, "TikTok preview unavailable.")
		tiktokEmbedClearInFlight(rawURL)
		return
	}

	tiktokEmbedStoreFound(ctx, rawURL, title, thumb)
	tiktokEmbedClearInFlight(rawURL)
}

type tiktokOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveTikTokEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	oembedURL := "https://www.tiktok.com/oembed?url=" + url.QueryEscape(rawURL)
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload tiktokOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if title == "" || thumb == "" {
		return "", "", false
	}
	return title, thumb, true
}

func resolveInstagramEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveInstagramEmbedWithClient(rawURL, client)
}

func resolveInstagramEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveInstagramEmbedWithClient(rawURL, instagramEmbedHTTPClient)
	if !ok {
		instagramEmbedStoreFailure(ctx, rawURL, "Instagram preview unavailable.")
		instagramEmbedClearInFlight(rawURL)
		return
	}

	instagramEmbedStoreFound(ctx, rawURL, title, thumb)
	instagramEmbedClearInFlight(rawURL)
}

type instagramOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveInstagramEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	accessToken := strings.TrimSpace(os.Getenv("WIKI_INSTAGRAM_OEMBED_TOKEN"))
	var oembedURL string
	if accessToken != "" {
		oembedURL = "https://graph.facebook.com/v19.0/instagram_oembed?url=" +
			url.QueryEscape(rawURL) + "&access_token=" + url.QueryEscape(accessToken)
	} else {
		oembedURL = "https://www.instagram.com/oembed?url=" + url.QueryEscape(rawURL)
	}
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload instagramOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if thumb == "" {
		return "", "", false
	}
	if title == "" {
		title = "Instagram Reel"
	}
	return title, thumb, true
}

func resolveYouTubeEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveYouTubeEmbedWithClient(rawURL, client)
}

func resolveYouTubeEmbedAsync(ctx context.Context, rawURL string) {
	title, thumb, ok := resolveYouTubeEmbedWithClient(rawURL, youtubeEmbedHTTPClient)
	if !ok {
		youtubeEmbedStoreFailure(ctx, rawURL, "YouTube preview unavailable.")
		youtubeEmbedClearInFlight(rawURL)
		return
	}

	youtubeEmbedStoreFound(ctx, rawURL, title, thumb)
	youtubeEmbedClearInFlight(rawURL)
}

type youtubeOEmbed struct {
	Title        string `json:"title"`
	ThumbnailURL string `json:"thumbnail_url"`
}

func resolveYouTubeEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	oembedURL := "https://www.youtube.com/oembed?format=json&url=" + url.QueryEscape(rawURL)
	req, err := http.NewRequest(http.MethodGet, oembedURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	var payload youtubeOEmbed
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", false
	}
	title := strings.TrimSpace(payload.Title)
	thumb := strings.TrimSpace(payload.ThumbnailURL)
	if title == "" || thumb == "" {
		return "", "", false
	}
	return title, thumb, true
}

func resolveChatGPTEmbedNow(rawURL string, timeout time.Duration) (string, string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveChatGPTEmbedWithClient(rawURL, client)
}

func resolveChatGPTEmbedAsync(ctx context.Context, rawURL string) {
	title, preview, ok := resolveChatGPTEmbedWithClient(rawURL, chatgptEmbedHTTPClient)
	if !ok {
		chatgptEmbedStoreFailure(ctx, rawURL, "ChatGPT preview unavailable.")
		chatgptEmbedClearInFlight(rawURL)
		return
	}

	chatgptEmbedStoreFound(ctx, rawURL, title, preview)
	chatgptEmbedClearInFlight(rawURL)
}

func resolveChatGPTEmbedWithClient(rawURL string, client *http.Client) (string, string, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", false
	}
	htmlStr := string(body)
	title := extractMetaContent(htmlStr, "og:title")
	if title == "" {
		title = extractTitleTag(htmlStr)
	}
	preview := extractMetaContent(htmlStr, "og:description")
	if preview == "" {
		preview = extractMetaContent(htmlStr, "description")
	}
	title = strings.TrimSpace(title)
	preview = strings.TrimSpace(preview)
	if title == "" {
		return "", "", false
	}
	return title, preview, true
}

func tiktokEmbedIsInFlight(rawURL string) bool {
	return tiktokEmbedInFlight.IsActive(rawURL, time.Now())
}

func tiktokEmbedMarkInFlight(rawURL string) {
	tiktokEmbedInFlight.Upsert(rawURL, time.Now().Add(tiktokEmbedPendingTTL))
}

func tiktokEmbedClearInFlight(rawURL string) {
	tiktokEmbedInFlight.Delete(rawURL)
}

func tiktokEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      tiktokEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(tiktokEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func tiktokEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      tiktokEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(tiktokEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func instagramEmbedIsInFlight(rawURL string) bool {
	return instagramEmbedInFlight.IsActive(rawURL, time.Now())
}

func instagramEmbedMarkInFlight(rawURL string) {
	instagramEmbedInFlight.Upsert(rawURL, time.Now().Add(instagramEmbedPendingTTL))
}

func instagramEmbedClearInFlight(rawURL string) {
	instagramEmbedInFlight.Delete(rawURL)
}

func instagramEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      instagramEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(instagramEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func instagramEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      instagramEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(instagramEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func chatgptEmbedIsInFlight(rawURL string) bool {
	return chatgptEmbedInFlight.IsActive(rawURL, time.Now())
}

func chatgptEmbedMarkInFlight(rawURL string) {
	chatgptEmbedInFlight.Upsert(rawURL, time.Now().Add(chatgptEmbedPendingTTL))
}

func chatgptEmbedClearInFlight(rawURL string) {
	chatgptEmbedInFlight.Delete(rawURL)
}

func chatgptEmbedStoreFound(ctx context.Context, rawURL string, title string, preview string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      chatgptEmbedCacheKind,
		EmbedURL:  preview,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(chatgptEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func chatgptEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      chatgptEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(chatgptEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func youtubeEmbedIsInFlight(rawURL string) bool {
	return youtubeEmbedInFlight.IsActive(rawURL, time.Now())
}

func youtubeEmbedMarkInFlight(rawURL string) {
	youtubeEmbedInFlight.Upsert(rawURL, time.Now().Add(youtubeEmbedPendingTTL))
}

func youtubeEmbedClearInFlight(rawURL string) {
	youtubeEmbedInFlight.Delete(rawURL)
}

func youtubeEmbedStoreFound(ctx context.Context, rawURL string, title string, thumb string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      youtubeEmbedCacheKind,
		EmbedURL:  thumb,
		Status:    index.EmbedCacheStatusFound,
		ErrorMsg:  title,
		UpdatedAt: now,
		ExpiresAt: now.Add(youtubeEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func youtubeEmbedStoreFailure(ctx context.Context, rawURL string, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       rawURL,
		Kind:      youtubeEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(youtubeEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func lookupMapsEmbed(ctx context.Context, shortURL string) (mapsEmbedStatus, string, string) {
	if embedCacheStore != nil {
		entry, ok, err := embedCacheStore.GetEmbedCache(ctx, shortURL, mapsEmbedCacheKind)
		if err == nil && ok {
			if entry.Status == index.EmbedCacheStatusFound {
				return mapsEmbedStatusFound, entry.EmbedURL, ""
			}
			if entry.Status == index.EmbedCacheStatusFailed {
				message := entry.ErrorMsg
				if message == "" {
					message = "Map preview unavailable."
				}
				return mapsEmbedStatusFailed, "", message
			}
		}
	}

	if mapsEmbedIsInFlight(shortURL) {
		return mapsEmbedStatusPending, "", ""
	}
	mapsEmbedMarkInFlight(shortURL)

	if embedURL, ok := resolveMapsEmbedNow(shortURL, mapsEmbedSyncTimeout); ok {
		mapsEmbedStoreFound(ctx, shortURL, embedURL)
		mapsEmbedClearInFlight(shortURL)
		return mapsEmbedStatusFound, embedURL, ""
	}

	go resolveMapsEmbedAsync(context.WithoutCancel(ctx), shortURL)
	return mapsEmbedStatusPending, "", ""
}

func resolveMapsEmbedNow(shortURL string, timeout time.Duration) (string, bool) {
	client := &http.Client{Timeout: timeout}
	return resolveMapsEmbedWithClient(shortURL, client)
}

func resolveMapsEmbedAsync(ctx context.Context, shortURL string) {
	embedURL, ok := resolveMapsEmbedWithClient(shortURL, mapsEmbedHTTPClient)
	if !ok {
		mapsEmbedStoreFailure(ctx, shortURL, "Map preview unavailable.")
		mapsEmbedClearInFlight(shortURL)
		return
	}

	mapsEmbedStoreFound(ctx, shortURL, embedURL)
	mapsEmbedClearInFlight(shortURL)
}

func resolveMapsEmbedWithClient(shortURL string, client *http.Client) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, shortURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "gwiki")
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	_ = resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if embedURL, ok := buildMapsEmbedURL(finalURL); ok {
		return embedURL, true
	}

	if linkValue := strings.TrimSpace(resp.Request.URL.Query().Get("link")); linkValue != "" {
		if decoded, err := url.QueryUnescape(linkValue); err == nil {
			if embedURL, ok := buildMapsEmbedURL(decoded); ok {
				return embedURL, true
			}
		}
	}

	return "", false
}

func mapsEmbedIsInFlight(shortURL string) bool {
	return mapsEmbedInFlight.IsActive(shortURL, time.Now())
}

func mapsEmbedMarkInFlight(shortURL string) {
	mapsEmbedInFlight.Upsert(shortURL, time.Now().Add(mapsEmbedPendingTTL))
}

func mapsEmbedClearInFlight(shortURL string) {
	mapsEmbedInFlight.Delete(shortURL)
}

func mapsEmbedStoreFound(ctx context.Context, shortURL, embedURL string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       shortURL,
		Kind:      mapsEmbedCacheKind,
		EmbedURL:  embedURL,
		Status:    index.EmbedCacheStatusFound,
		UpdatedAt: now,
		ExpiresAt: now.Add(mapsEmbedSuccessTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

func mapsEmbedStoreFailure(ctx context.Context, shortURL, message string) {
	if embedCacheStore == nil {
		return
	}
	now := time.Now()
	entry := index.EmbedCacheEntry{
		URL:       shortURL,
		Kind:      mapsEmbedCacheKind,
		Status:    index.EmbedCacheStatusFailed,
		ErrorMsg:  message,
		UpdatedAt: now,
		ExpiresAt: now.Add(mapsEmbedFailureTTL),
	}
	_ = embedCacheStore.UpsertEmbedCache(ctx, entry)
}

type ttlLRUCache struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	lru      *list.List
}

type ttlLRUEntry struct {
	key     string
	expires time.Time
}

func newTTLCache(capacity int) *ttlLRUCache {
	if capacity < 1 {
		capacity = 1
	}
	return &ttlLRUCache{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
	}
}

func (c *ttlLRUCache) IsActive(key string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.items[key]
	if !ok {
		return false
	}
	entry := elem.Value.(ttlLRUEntry)
	if entry.expires.After(now) {
		c.lru.MoveToFront(elem)
		return true
	}
	c.lru.Remove(elem)
	delete(c.items, key)
	return false
}

func (c *ttlLRUCache) Upsert(key string, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		elem.Value = ttlLRUEntry{key: key, expires: expires}
		c.lru.MoveToFront(elem)
		return
	}
	elem := c.lru.PushFront(ttlLRUEntry{key: key, expires: expires})
	c.items[key] = elem
	if c.lru.Len() > c.capacity {
		c.evictOldest()
	}
}

func (c *ttlLRUCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elem, ok := c.items[key]; ok {
		c.lru.Remove(elem)
		delete(c.items, key)
	}
}

func (c *ttlLRUCache) evictOldest() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}
	entry := elem.Value.(ttlLRUEntry)
	delete(c.items, entry.key)
	c.lru.Remove(elem)
}

func buildMapsEmbedURL(finalURL string) (string, bool) {
	parsed, err := url.Parse(finalURL)
	if err != nil || parsed.Host == "" {
		return "", false
	}

	if coords := mapsEmbedCoordsRegexp.FindStringSubmatch(finalURL); len(coords) == 3 {
		return mapsEmbedQueryURL(coords[1] + "," + coords[2]), true
	}

	queryValue := strings.TrimSpace(parsed.Query().Get("q"))
	if queryValue != "" {
		return mapsEmbedQueryURL(queryValue), true
	}

	if ll := strings.TrimSpace(parsed.Query().Get("ll")); ll != "" {
		return mapsEmbedQueryURL(ll), true
	}

	path := parsed.EscapedPath()
	if strings.HasPrefix(path, "/maps/place/") {
		trimmed := strings.TrimPrefix(path, "/maps/place/")
		segment := strings.SplitN(trimmed, "/", 2)[0]
		if segment != "" {
			if decoded, err := url.PathUnescape(segment); err == nil {
				segment = decoded
			}
			segment = strings.TrimSpace(segment)
			if segment != "" {
				return mapsEmbedQueryURL(segment), true
			}
		}
	}

	if strings.HasPrefix(path, "/maps/search/") {
		trimmed := strings.TrimPrefix(path, "/maps/search/")
		segment := strings.SplitN(trimmed, "/", 2)[0]
		if segment != "" {
			if decoded, err := url.PathUnescape(segment); err == nil {
				segment = decoded
			}
			segment = strings.TrimSpace(segment)
			if segment != "" {
				return mapsEmbedQueryURL(segment), true
			}
		}
	}

	return "", false
}

func mapsEmbedQueryURL(value string) string {
	return "https://www.google.com/maps?output=embed&q=" + url.QueryEscape(value)
}
