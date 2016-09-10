use Bitwise

defmodule S1C8 do
  def dists(body, n1, n2) do
    n1..n2
    |> Enum.map(fn (n) -> {n, dist_for_size(body, n)} end)
    |> Enum.sort_by(fn ({_n, d}) -> d end)
  end

  def dist_for_size(body, size) do
    dists = all_dists(Enum.chunk body, size)
    Enum.sum(dists) / length(dists)
  end

  def all_dists([]) do
    []
  end
  def all_dists([chunk | rest]) do
    len = length(chunk)
    Enum.map(rest, fn (c) -> ham_dist(chunk, c) / len end) ++ all_dists(rest)
  end

  def ham_dist(l1, l2) do
    Enum.map(fixed_xor(l1, l2), fn (n) ->
      for(<< bit::1 <- :binary.encode_unsigned(n)>>, do: bit) |> Enum.sum
    end)
    |> Enum.sum
  end

  def fixed_xor(l1, l2) do
    Enum.zip(l1, l2)
    |> Enum.map(fn ({b1, b2}) -> b1 ^^^ b2 end)
  end

  def count_repeats(line, chunk_size) do
    count_repeats Enum.chunk(line, chunk_size)
  end
  def count_repeats([]) do
    0
  end
  def count_repeats([chunk | rest]) do
    Enum.count(rest, &(&1 == chunk)) + count_repeats(rest)
  end
end

path = "1/8.txt"
lines = path
|> File.read!
|> String.split
|> Enum.map(fn (l) -> Base.decode16!(l, case: :lower) end)
|> Enum.map(&:binary.bin_to_list/1)

IO.inspect ['num lines', length(lines)]

# Find the line w/ ham dist over every permutation for a variety of key lengths

dists = lines |> Enum.with_index |> Enum.map(fn ({l, idx}) ->
  {idx, hd(S1C8.dists(l, 4, 20))}
end) |> Enum.sort_by(fn ({_idx, {_n, dist}}) -> dist end)

IO.inspect(dists)
{best, {keylen, _}} = hd(dists)
IO.inspect [best, keylen]

best_line = Enum.at(lines, best)

IO.inspect [best_line, Base.encode16(IO.iodata_to_binary(best_line), case: :lower)]

# Find the same line by counting repeated chunks, assuming key length

repeats = lines |> Enum.with_index |> Enum.map(fn ({l, idx}) ->
  {idx, S1C8.count_repeats(l, 16)}
end) |> Enum.sort_by(fn ({_idx, n}) -> -n end)

IO.inspect hd(repeats)
