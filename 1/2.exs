use Bitwise

defmodule S1C2 do

  def fixed_xor(hex1, hex2) do
    [bytes1, bytes2] = Enum.map([hex1, hex2], &hex_to_bytes/1)
    Enum.zip(bytes1, bytes2)
    |> Enum.map(fn ({n1, n2}) -> n1 ^^^ n2 end)
    |> bytes_to_hex
  end

  def bytes_to_hex(bytes) do
    bytes
    |> Enum.map(&byte_to_hex/1)
    |> Enum.join
  end

  def hex_to_bytes(hex) do
    hex |> Enum.chunk(2, 2, [0, 0]) |> Enum.map(&hexbyte/1)
  end

  @hex_vals List.to_tuple('0123456789abcdef')
  @hex_map @hex_vals
  |> Tuple.to_list
  |> Enum.with_index
  |> Enum.map(fn ({n, idx}) -> {n, idx} end)
  |> Map.new()

  defp byte_to_hex(byte) do
    [(byte &&& 0xF0) >>> 4, byte &&& 0x0F]
    |> Enum.map(fn (n) -> elem(@hex_vals, n) end)
    |> to_string
  end

  defp hexbyte(chunk) do
    [n1, n2] = Enum.map chunk, &hexval/1
    (n1 <<< 4) + n2
  end
  defp hexval(cp) do
    @hex_map[cp]
  end
end

hex1 = '1c0111001f010100061a024b53535009181c'
hex2 = '686974207468652062756c6c277320657965'

tar = "746865206b696420646f6e277420706c6179"

IO.inspect ['1', hex1, S1C2.hex_to_bytes(hex1)]
IO.inspect ['2', hex2, S1C2.hex_to_bytes(hex2)]
IO.inspect ['t', tar]
IO.inspect ['o', S1C2.fixed_xor(hex1, hex2)]
IO.inspect ['o', S1C2.fixed_xor(hex2, hex1)]

IO.inspect ['r', tar == S1C2.fixed_xor(hex1, hex2)]
