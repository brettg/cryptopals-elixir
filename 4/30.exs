use Bitwise

defmodule CryptUtils do
  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
end

defmodule MD5 do
  @s [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

  @k (for i <- 1..64, do: trunc(abs(:math.sin(i) * :math.pow(2, 32))) &&& 0xFFFFFFFF)

  @init [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

  def digest(msg, init \\ @init) do
    digest_padded(msg ++ padding(length(msg)), init)
  end

  # https://en.wikipedia.org/wiki/MD5#Pseudocode
  def digest_padded(padded_msg, init) do
    Enum.chunk(padded_msg, 64)
    |> Enum.reduce(init, fn(chunk, vals) ->
      m = bytes_to_int32s(chunk)

      Enum.zip(0..63, @s)
      |> Enum.zip(@k)
      |> Enum.reduce(vals, fn({{i, s}, k}, [a, b, c, d]) ->
        {f, g} = case i do
          x when x in  0..15 -> {(b &&& c) ||| ((~~~b) &&& d), x}
          x when x in 16..31 -> {(d &&& b) ||| ((~~~d) &&& c), rem(5 * x + 1, 16)}
          x when x in 32..47 -> {b ^^^ c ^^^ d,                rem(3 * x + 5, 16)}
          x when x in 48..63 -> {c ^^^ (b ||| (~~~d)),         rem(7 * x, 16)}
        end

        new_b = trunc32(b + lotate(trunc32(a + f + k + Enum.at(m, g)), s))
        [d, new_b, b, c]
      end)
      |> Enum.zip(vals)
      |> Enum.map(fn({v, v0}) -> trunc32(v + v0) end)
    end)
    |> int32s_to_bytes
  end

  def padding(len) do
    zero_l = 56 - rem((len + 1), 64)
    zero_l = if zero_l < 0, do: 56 + (8 + zero_l), else: zero_l
    [0x80] ++ zeros(zero_l) ++ (<< len * 8 :: little-size(64) >> |> :binary.bin_to_list)
  end

  def hexdigest(msg, init \\ @init), do: digest(msg, init) |> Base.encode16

  defp zeros(0), do: []
  defp zeros(n), do: for _ <- 1..n, do: 0

  defp lotate(i, n), do: trunc32((i <<< n) ^^^ (i >>> (32 - n)))

  def trunc32(n), do: n &&& 0xFFFFFFFF

  # List of bytes converted to little endian 32-bit
  def bytes_to_int32s(bs) do
    Enum.chunk(bs, 4)
    |> Enum.map(&IO.iodata_to_binary/1)
    |> Enum.map(fn(chunk)-> for << n::little-size(32) <- chunk >>, do: n end)
    |> List.flatten
  end

  # List of 32-bit integers converted to little endian bytestring
  defp int32s_to_bytes(ints) do
    Enum.map(ints, fn(int)->
      bytes = Integer.digits(int, 256) |> Enum.reverse
      bytes ++ zeros(4 - length(bytes))
    end)
    |> List.flatten
    |> IO.iodata_to_binary
  end
end


defmodule S4C30 do

  ## MD5 Implementation Testing

  defp test(input) do
    expected = :crypto.hash(:md5, input) |> Base.encode16
    result = MD5.hexdigest(input)

    if expected != result do
      IO.puts "Failed test for: #{input}"
      IO.inspect [expected, result]
      exit(:bad)
    end
  end
  def run_md5_tests do
    Enum.each ['cats', 'frogs', 'dogs'], &test/1
    for _ <- 1..300, do: test(rand_words)
    IO.inspect "All tests passed!"
  end

  @words File.read!('/usr/share/dict/propernames')
  |> String.split

  defp rand_words do
    Enum.take_random(@words, :rand.uniform(300))
    |> Enum.join(" ")
    |> to_charlist
  end

  ## Actual Challenge

  @key CryptUtils.rand_bytes(:rand.uniform(12) + 6)
  @authed 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'

  defp mac(msg) do
    MD5.hexdigest(@key ++ msg)
  end

  def output do
    {@authed, mac(@authed)}
  end

  def verify(input, hexdigest) do
    hexdigest == mac(input)
  end

  def check_key_length(l) do
    IO.inspect ["Key length correct:", length(@key) == l]
  end
end

# MD5 Test
#
S4C30.run_md5_tests

# Actual Challenge
#
{msg, hash} = S4C30.output

ml = length(msg)
payload = ';admin=true'
new_init = Base.decode16!(hash) |> :binary.bin_to_list |> MD5.bytes_to_int32s

IO.inspect new_init

for i <- 1..40 do
  glue_pad = MD5.padding(ml + i)
  final_pad = MD5.padding(ml + i + length(glue_pad) + length(payload))

  last_part = payload ++ final_pad

  new_hash = MD5.digest_padded(last_part, new_init) |> Base.encode16
  new_msg = msg ++ glue_pad ++ payload

  if S4C30.verify(new_msg, new_hash) do
    IO.puts "Prefix Length Found! #{i}"
    IO.inspect [new_msg, new_hash]
    S4C30.check_key_length(i)
  end
end
