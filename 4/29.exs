use Bitwise

defmodule CryptUtils do
  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)
  def rand_lowercase(n), do: (for _ <- 1..n, do: 96 + :rand.uniform(26))

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)
end

defmodule SHA1 do
  @z [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

  def digest(msg, z \\ @z), do: digest_raw(pad(msg), z)

  def digest_raw(padded_msg, z) do
    chunks = Enum.chunk(padded_msg, 64)

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

  def hexdigest(msg, z \\ @z), do: digest(msg, z) |> Base.encode16
  def digest64(msg, z \\ @z), do: digest(msg, z) |> Base.encode64

  def pad(msg), do: msg ++ padding(length(msg))

  def padding(ml) do
    zero_l = 56 - rem((ml + 1), 64)
    zero_l = if zero_l < 0, do: 56 + (8 + zero_l), else: zero_l
    [0x80] ++ zeros(zero_l) ++ (<< ml * 8 :: size(64) >> |> :binary.bin_to_list)
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

defmodule S4C29 do
  @key CryptUtils.rand_bytes(:rand.uniform(12) + 6)
  @authed 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'

  defp sha1_mac(input) do
    SHA1.hexdigest(@key ++ input)
  end

  def output do
    {@authed, sha1_mac(@authed)}
  end

  def verify(input, hexdigest) do
    hexdigest == sha1_mac(input)
  end

  def bytes_to_int32s(bytes) do
    :binary.bin_to_list(bytes)
    |> Enum.chunk(4)
    |> Enum.map(fn(bs) -> Integer.undigits(bs, 256) end)
  end

  def check_key do
    IO.inspect [length(@key), @key]
  end
end

# Make sure changes to SHA1 have not created regression.
#IO.inspect [SHA1.hexdigest('cats'),
#            :crypto.hash(:sha, 'cats') |> Base.encode16,
#            (:crypto.hash(:sha, 'cats') |> Base.encode16) == SHA1.hexdigest('cats')]

{msg, hash} = S4C29.output

#IO.inspect S4C29.verify(msg, hash)
#IO.inspect S4C29.verify(msg ++ 'a', hash)

ml = length(msg)
payload = ';admin=true'
new_init = Base.decode16!(hash) |> S4C29.bytes_to_int32s

for i <- 1..40 do
  glue_pad = SHA1.padding(ml + i)
  final_pad = SHA1.padding(ml + i + length(glue_pad) + length(payload))

  last_part = payload ++ final_pad

  new_hash = SHA1.digest_raw(last_part, new_init) |> Base.encode16
  new_msg = msg ++ glue_pad ++ payload


  if S4C29.verify(new_msg, new_hash) do
    IO.puts "Prefix Length Found! #{i}"
    IO.inspect [new_msg, new_hash]
    S4C29.check_key
  end
end

