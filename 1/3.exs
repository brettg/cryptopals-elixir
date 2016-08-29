use Bitwise

defmodule S1C3 do

  def try_all(input) do
    inputB = hex_to_bytes(input)

    {_, best} = Enum.reduce 0..255, {0, nil}, fn (n,  {most, best}) ->
      spaces = Enum.count(single_char_xor(n, inputB), fn (c) -> c == 32 end)

      if spaces > most do
        {spaces, n}
      else
        {most, best}
      end
    end

    IO.inspect [best, [best], single_char_xor(best, inputB)]
  end

  def single_char_xor(char, inputB) do
    fixed_xor(inputB, (for _ <- 1..length(inputB), do: char))
  end


  def fixed_xor(bytes1, bytes2) do
    Enum.zip(bytes1, bytes2)
    |> Enum.map(fn ({n1, n2}) -> n1 ^^^ n2 end)
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

input = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

IO.inspect ['i', input]
S1C3.try_all(input)
