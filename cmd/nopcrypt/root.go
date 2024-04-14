package nopcrypt

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const Version = "1.0.0"

var rootCmd = &cobra.Command{
	Use:     "nopcrypt",
	Version: Version,
	Short:   "nopcrypt - encrypt / decrypt files using asimetric cryptography",
	Long: `
	nopcrypt - encrypt / decrypt files using asimetric cryptography
		encrypt - encrypt files 
		decrypt - decrypt files
	`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "\n\n")
		os.Exit(1)
	}
}
