#!/bin/sh

read_and_pipe() {
  while read filename; do
    echo > /dev/tty
    echo $filename > /dev/tty
    echo $filename
  done
}

fswatch **/*.exs | read_and_pipe | xargs -n 1 elixir
