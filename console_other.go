//go:build !windows

package main

func initConsole() {}

func consoleWidth() int { return 80 }
