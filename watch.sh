#!/bin/sh

fswatch **/*.exs | tee /dev/tty | xargs -n 1 elixir
