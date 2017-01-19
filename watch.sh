#!/bin/bash

read_and_pipe() {
  while read filename; do
    echo > /dev/tty
    echo $filename > /dev/tty
    echo $filename
  done
}

fswatch */[0-9][0-9].exs **/**/[0-9][0-9].exs | read_and_pipe | xargs -n 1 elixir
