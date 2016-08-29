use Bitwise

defmodule Set1 do

  def hex_to_64(hex) do
    hex |> hex_to_bytes |> bytes_to_64
  end

  def bytes_to_64(bytes) do
    bytes
    |> Enum.chunk(3, 3, [0, 0, 0])
    |> Enum.map(&base_64_pair/1)
    |> Enum.join
  end

  @base64 List.to_tuple 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  defp base_64_pair([b1, b2, b3]) do
    [
      (b1 &&& 0b11111100) >>> 2,
      ((b1 &&& 0b11) <<< 4) + ((b2 &&& 0b11110000) >>> 4),
      ((b2 &&& 0b1111) <<< 2) + ((b3 &&& 0b11000000) >>> 6),
      (b3 &&& 0b111111)
    ]
    |> Enum.map(&base_val/1)
    |> to_string
  end

  defp base_val(n) do
    elem(@base64, n)
  end

  @hex_vals '0123456789abcdef'
  |> Enum.with_index
  |> Enum.map(fn ({n, idx}) -> {n, idx} end)
  |> Map.new()

  def hex_to_bytes(hex) do
    hex |> Enum.chunk(2, 2, [0, 0]) |> Enum.map(&hexbyte/1)
  end

  defp hexbyte(chunk) do
    [n1, n2] = Enum.map chunk, &hexval/1
    (n1 <<< 4) + n2
  end
  defp hexval(cp) do
    @hex_vals[cp]
  end
end

hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
six4 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

converted = Set1.hex_to_64(hex)
IO.inspect [length(hex), hex]
IO.inspect [String.length(six4), six4]
IO.inspect [String.length(converted), converted]
IO.puts six4 == Set1.hex_to_64(hex)

