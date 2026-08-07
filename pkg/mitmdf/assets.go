package mitmdf

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// AssetList mirrors the geosite/geoip filenames expected by xray-core.
var requiredAssets = []struct {
	Name    string
	URL     string
	Display string
}{
	{
		Name:    "geosite.dat",
		URL:     "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
		Display: "geosite.dat (domain list)",
	},
	{
		Name:    "geoip.dat",
		URL:     "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
		Display: "geoip.dat (IP ranges)",
	},
}

func AssetsDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find home dir: %w", err)
	}
	dir := filepath.Join(home, ".xray-knife", "assets")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create assets dir %s: %w", dir, err)
	}
	return dir, nil
}

type AssetStatus struct {
	Geosite bool `json:"geosite"`
	Geoip   bool `json:"geoip"`
}

func CheckAssets() (*AssetStatus, error) {
	dir, err := AssetsDir()
	if err != nil {
		return nil, err
	}
	status := &AssetStatus{}
	if _, err := os.Stat(filepath.Join(dir, "geosite.dat")); err == nil {
		status.Geosite = true
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip.dat")); err == nil {
		status.Geoip = true
	}
	return status, nil
}

type AssetProgress struct {
	Current string `json:"current,omitempty"`
	Total   int    `json:"total"`
	Done    int    `json:"done"`
	Error   string `json:"error,omitempty"`
}

type AssetCallback func(progress AssetProgress)

func DownloadAssets(cb AssetCallback) error {
	dir, err := AssetsDir()
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 5 * time.Minute}

	for i, asset := range requiredAssets {
		dest := filepath.Join(dir, asset.Name)

		if cb != nil {
			cb(AssetProgress{Current: asset.Display, Total: len(requiredAssets), Done: i})
		}

		tmpDest := dest + ".tmp"
		out, err := os.Create(tmpDest)
		if err != nil {
			return fmt.Errorf("failed to create %s: %w", asset.Name, err)
		}

		resp, err := client.Get(asset.URL)
		if err != nil {
			out.Close()
			os.Remove(tmpDest)
			return fmt.Errorf("failed to download %s: %w", asset.Display, err)
		}

		if resp.StatusCode != http.StatusOK {
			out.Close()
			resp.Body.Close()
			os.Remove(tmpDest)
			return fmt.Errorf("bad status downloading %s: %s", asset.Display, resp.Status)
		}

		if _, err := io.Copy(out, resp.Body); err != nil {
			out.Close()
			resp.Body.Close()
			os.Remove(tmpDest)
			return fmt.Errorf("failed to write %s: %w", asset.Name, err)
		}
		out.Close()
		resp.Body.Close()

		if err := os.Rename(tmpDest, dest); err != nil {
			return fmt.Errorf("failed to rename %s: %w", asset.Name, err)
		}

		if cb != nil {
			cb(AssetProgress{Current: asset.Display, Total: len(requiredAssets), Done: i + 1})
		}
	}

	return nil
}
