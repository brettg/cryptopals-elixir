use Bitwise

defmodule SHA1 do
  @h0 0x67452301
  @h1 0xEFCDAB89
  @h2 0x98BADCFE
  @h3 0x10325476
  @h4 0xC3D2E1F0

  # https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
  # https://gist.github.com/tstevens/925415
  # https://github.com/ajalt/python-sha1/blob/master/sha1.py
  def hash(msg) do
    ml = length(msg)
    msg = msg ++ [0x80]
    zero_l = 56 - rem((ml + 1), 64)
    zero_l = if zero_l < 0, do: 56 + (8 + zero_l), else: zero_l
    msg = msg ++ zeros(zero_l)
    msg = msg ++ (<< ml * 8 :: size(64) >> |> :binary.bin_to_list)

    z = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    chunks = Enum.chunk(msg, 64)

    z = Enum.reduce(chunks, z, fn(chunk, z) ->
      w = Enum.chunk(chunk, 4)
      |> Enum.map(fn([a1, b1, c1, d1]) -> (((((a1 <<< 8) ^^^ b1) <<< 8) ^^^ c1) <<< 8) ^^^ d1 end)

      w = Enum.reduce(16..79, w, fn(i, a) ->
        n = Enum.at(a, i - 3) ^^^ Enum.at(a, i - 8) ^^^ Enum.at(a, i - 14) ^^^ Enum.at(a, i - 16)
        a ++ [lotate(n)]
      end)

      [a, b, c, d, e] = Enum.reduce 0..79, z, fn(i, [a, b, c, d, e]) ->
        {f, k} = case i do
          x when x in 0..19  -> {(b &&& c) ||| (~~~b &&& d), 0x5A827999}
          x when x in 20..39 -> {(b ^^^ c ^^^ d),  0x6ED9EBA1}
          x when x in 40..59 -> {(b &&& c) ||| (b &&& d) ||| (c &&& d), 0x8F1BBCDC}
          x when x in 60..79 -> {(b ^^^ c ^^^ d), 0xCA62C1D6}
        end

        temp = (lotate(a, 5) + f + e + k + Enum.at(w, i)) |> trunc32
        [temp, a, lotate(b, 30), c, d]
      end

      [za, zb, zc, zd, ze] = z
      Enum.map([za + a, zb + b, zc + c, zd + d, ze + e], &trunc32/1)
    end)

    int32s_to_bytes(z)
  end

  defp int32s_to_bytes(ints) do
    Enum.map(ints, fn(int)->
      bytes = Integer.digits(int, 256)
      zeros(4 - length(bytes)) ++ bytes
    end)
    |> List.flatten
    |> IO.iodata_to_binary
  end

  defp zeros(0), do: []
  defp zeros(n), do: for _ <- 1..n, do: 0

  defp lotate(i), do: lotate(i, 1)
  defp lotate(i, n), do: trunc32((i <<< n) ^^^ (i >>> (32 - n)))

  def trunc32(n), do: n &&& 0xFFFFFFFF
end

defmodule S4C28 do

  def test(input) do
    expected = :crypto.hash(:sha, input) |> Base.encode16
    result = SHA1.hash(input) |> Base.encode16

    IO.puts "testing: #{input}"
    if expected == result do
      IO.puts "\tGOOD!"
    else
      IO.inspect [expected, result]
      IO.puts "\tOH NO!"

      exit(:bad)
    end
  end

  @words File.read!('/usr/share/dict/propernames')
  |> String.split

  def rand_words do
    Enum.take_random(@words, :rand.uniform(200))
    |> Enum.join(" ")
    |> to_charlist
  end

  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)

  @key (for _ <- 1..16, do: :rand.uniform(0xff + 1) - 1)

  def sha1_mac(input) do
    SHA1.hash(@key ++ input) |> Base.encode16
  end
end

 # tests = ['cats', 'frogs', 'dogs',
 #          'jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj']

# Enum.each(tests, &S4C28.test/1)
# for _ <- 1..200, do: S4C28.test(S4C28.rand_words)

sig = S4C28.sha1_mac('cats are here')
IO.inspect ['Same sig generated', sig == S4C28.sha1_mac('cats are here')]
IO.inspect ['Different sig different input', sig != S4C28.sha1_mac('here are cats')]
