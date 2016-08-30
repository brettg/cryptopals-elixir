use Bitwise

defmodule S1C6 do
  # They are reversed but it should not matter for histogram
  def columnize(body, cols) do
    body
    |> to_charlist
    |> Enum.with_index
    |> Enum.reduce(%{}, fn ({n, idx}, holder) ->
      {_el, newH} = Map.get_and_update(holder, rem(idx, cols), &{&1, [n | (&1 || [])]})
      newH
    end)
  end

  def dists(body, n1, n2) do
    n1..n2
    |> Enum.map(fn (n) ->
      dist = S1C6.dist_for_size(body, n)
      {n, dist}
    end)
    |> Enum.sort_by(fn ({_n, d}) -> d end)
  end

  def dist_for_size(body, size) do
    times = 30

    dists = Enum.map 0..(times - 1), fn (n) ->
      ham_dist(Enum.slice(body, size * n, size), Enum.slice(body, size * (n + 1), size)) / size
    end

    Enum.sum(dists) / times
  end

  def best_fixed_xor(list) do
    llen = length(list)
    Enum.reduce 0..255, {0, nil}, fn (key,  {bestScore, bestKey}) ->
      score = hist_score(fixed_xor((for _n <- 0..llen, do: key), list))

      if score > bestScore do
        {score, key}
      else
        {bestScore, bestKey}
      end
    end
  end

  def hist_score(list) do
    list
    |> Enum.map(fn(n) ->
      case n do
        x when x in 'aeiou ' -> 3
        x when x in 'dlprst\n' -> 2
        x when x in 33..125 -> 1
        x when x < 9 or x in 14..31 or x in [127, 255] -> -1
        _ -> 0
      end
    end)
    |> Enum.sum
  end

  def rep_xor(list, key) do
    key_len = length(key)
    key_tup = List.to_tuple(key)
    list
    |> Enum.with_index
    |> Enum.map(fn ({b, idx}) ->  b ^^^ elem(key_tup, rem(idx, key_len)) end)
  end

  def fixed_xor(l1, l2) do
    Enum.zip(l1, l2)
    |> Enum.map(fn ({b1, b2}) -> b1 ^^^ b2 end)
  end


  def ham_dist(l1, l2) do
    Enum.map(fixed_xor(l1, l2), fn (n) ->
      for(<< bit::1 <- :binary.encode_unsigned(n)>>, do: bit) |> Enum.sum
    end)
    |> Enum.sum
  end
end

IO.inspect ['ham dist correct', 37 == S1C6.ham_dist('this is a test', 'wokka wokka!!!')]

path = "6.txt"
body = path
|> File.read!
|> String.split
|> Enum.join
|> Base.decode64!(ignore: :whitespace)
|> :binary.bin_to_list

dists = S1C6.dists(body, 2, 40)
{keysize, _best_dist} = hd(dists)

bests = Enum.map S1C6.columnize(body, keysize), fn ({_n, col}) -> S1C6.best_fixed_xor(col) end
key = for {_c, b} <- bests, do: b
IO.inspect [keysize, key]
IO.puts S1C6.rep_xor(body, key)


