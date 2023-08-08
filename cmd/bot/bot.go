package bot

import (
	"fmt"
	"github.com/spf13/cobra"
)

// BotCmd represents the bot command
var BotCmd = &cobra.Command{
	Use:   "bot",
	Short: "A Service to switch outbound connections automatically",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("bot called")
	},
}

func init() {
}
