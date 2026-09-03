// Package blockedservices backs Standard > Filters > Blocked Services:
// a fixed catalog of well-known internet services (name, category, real
// representative domains) an owner can toggle on/off, optionally on a
// schedule -- distinct from Advanced > Policy Profiles > Service
// Blocking Rulesets, which lets an owner define their OWN named,
// arbitrary-domain rulesets. Toggling a catalog service here compiles
// into a single reserved ruleset (RulesetID) assigned to the GLOBAL
// policy layer, which internal/dnsruntime's orchestrator now actually
// enforces (see its own doc comment on that fix).
package blockedservices

// Service is one catalog entry. Domains are real, representative
// hostnames for that service -- enough to block its main web/app
// traffic through the same suffix-match blocking every blocklist
// subscription already uses, not an exhaustive enumeration of every
// CDN/API host a large service might ever use.
type CatalogEntry struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"`
}

// Catalog is intentionally static (compiled into the binary, not
// owner-editable) -- matching the redesign spec's "Responsive service
// grid" for Standard mode. An owner who needs an arbitrary, self-defined
// list uses a Service Blocking Ruleset (Advanced > Policy Profiles)
// instead, which this package's own reserved ruleset sits alongside
// without conflicting (different ruleset ids).
var Catalog = []CatalogEntry{
	{ID: "facebook", Name: "Facebook", Category: "Social Media", Domains: []string{"facebook.com", "fbcdn.net", "fb.com"}},
	{ID: "instagram", Name: "Instagram", Category: "Social Media", Domains: []string{"instagram.com", "cdninstagram.com"}},
	{ID: "twitter", Name: "X (Twitter)", Category: "Social Media", Domains: []string{"twitter.com", "x.com", "twimg.com"}},
	{ID: "snapchat", Name: "Snapchat", Category: "Social Media", Domains: []string{"snapchat.com", "sc-cdn.net"}},
	{ID: "tiktok", Name: "TikTok", Category: "Social Media", Domains: []string{"tiktok.com", "tiktokcdn.com", "musical.ly"}},
	{ID: "reddit", Name: "Reddit", Category: "Social Media", Domains: []string{"reddit.com", "redd.it", "redditstatic.com"}},
	{ID: "linkedin", Name: "LinkedIn", Category: "Social Media", Domains: []string{"linkedin.com", "licdn.com"}},
	{ID: "pinterest", Name: "Pinterest", Category: "Social Media", Domains: []string{"pinterest.com", "pinimg.com"}},
	{ID: "tumblr", Name: "Tumblr", Category: "Social Media", Domains: []string{"tumblr.com"}},

	{ID: "youtube", Name: "YouTube", Category: "Video Streaming", Domains: []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"}},
	{ID: "netflix", Name: "Netflix", Category: "Video Streaming", Domains: []string{"netflix.com", "nflxvideo.net", "nflximg.net"}},
	{ID: "twitch", Name: "Twitch", Category: "Video Streaming", Domains: []string{"twitch.tv", "ttvnw.net", "jtvnw.net"}},
	{ID: "hulu", Name: "Hulu", Category: "Video Streaming", Domains: []string{"hulu.com", "hulustream.com"}},
	{ID: "disneyplus", Name: "Disney+", Category: "Video Streaming", Domains: []string{"disneyplus.com", "disney-plus.net", "dssott.com"}},
	{ID: "primevideo", Name: "Prime Video", Category: "Video Streaming", Domains: []string{"primevideo.com"}},
	{ID: "vimeo", Name: "Vimeo", Category: "Video Streaming", Domains: []string{"vimeo.com", "vimeocdn.com"}},

	{ID: "steam", Name: "Steam", Category: "Gaming", Domains: []string{"steampowered.com", "steamcommunity.com", "steamstatic.com"}},
	{ID: "epicgames", Name: "Epic Games", Category: "Gaming", Domains: []string{"epicgames.com", "unrealengine.com"}},
	{ID: "roblox", Name: "Roblox", Category: "Gaming", Domains: []string{"roblox.com", "rbxcdn.com"}},
	{ID: "minecraft", Name: "Minecraft", Category: "Gaming", Domains: []string{"minecraft.net"}},
	{ID: "xboxlive", Name: "Xbox Live", Category: "Gaming", Domains: []string{"xboxlive.com", "xbox.com"}},
	{ID: "playstation", Name: "PlayStation Network", Category: "Gaming", Domains: []string{"playstation.com", "playstation.net"}},
	{ID: "discord", Name: "Discord", Category: "Gaming", Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net"}},

	{ID: "whatsapp", Name: "WhatsApp", Category: "Messaging", Domains: []string{"whatsapp.com", "whatsapp.net"}},
	{ID: "telegram", Name: "Telegram", Category: "Messaging", Domains: []string{"telegram.org", "t.me"}},
	{ID: "messenger", Name: "Messenger", Category: "Messaging", Domains: []string{"messenger.com"}},
	{ID: "skype", Name: "Skype", Category: "Messaging", Domains: []string{"skype.com"}},
	{ID: "wechat", Name: "WeChat", Category: "Messaging", Domains: []string{"wechat.com", "weixin.qq.com"}},

	{ID: "spotify", Name: "Spotify", Category: "Music", Domains: []string{"spotify.com", "scdn.co"}},
	{ID: "soundcloud", Name: "SoundCloud", Category: "Music", Domains: []string{"soundcloud.com", "sndcdn.com"}},
	{ID: "applemusic", Name: "Apple Music", Category: "Music", Domains: []string{"music.apple.com"}},

	{ID: "amazon", Name: "Amazon", Category: "Shopping", Domains: []string{"amazon.com", "amazon.co.uk", "amazon.de"}},
	{ID: "ebay", Name: "eBay", Category: "Shopping", Domains: []string{"ebay.com"}},
	{ID: "etsy", Name: "Etsy", Category: "Shopping", Domains: []string{"etsy.com"}},

	{ID: "9gag", Name: "9GAG", Category: "Entertainment", Domains: []string{"9gag.com"}},
	{ID: "imgur", Name: "Imgur", Category: "Entertainment", Domains: []string{"imgur.com"}},
}

// ByID looks up one catalog entry, or nil if id isn't real.
func ByID(id string) *CatalogEntry {
	for i := range Catalog {
		if Catalog[i].ID == id {
			return &Catalog[i]
		}
	}
	return nil
}
