use Bitwise

defmodule S1C4 do
  def try_each(hexes) do
    for hex <- hexes  do
      {spaces, char, result} = best_single_xor(hex)
      if spaces > 4 do
        IO.inspect  [spaces, char, [char], hex, result]
      end
    end
  end

  def best_single_xor(hex) do
    bytes = Base.decode16!(hex, case: :mixed)

    {most, best} = Enum.reduce 0..255, {0, nil}, fn (n,  {most, best}) ->
      spaces = Enum.count(single_char_xor(n, bytes), fn (c) -> c == 32 end)
      nulls = Enum.count(single_char_xor(n, bytes), fn (c) -> c == 0 end)

      if nulls == 0 and spaces > most do
        {spaces, n}
      else
        {most, best}
      end
    end

    {most, best, single_char_xor(best, bytes)}
  end

  def single_char_xor(char, bytes) do
    fixed_xor((for <<n <- bytes>>, do: n), (for _ <- 1..byte_size(bytes), do: char))
  end


  def fixed_xor(bytes1, bytes2) do
    Enum.zip(bytes1, bytes2)
    |> Enum.map(fn ({n1, n2}) -> n1 ^^^ n2 end)
  end
end


path = "4.txt"
body = File.read!(path)

body |> String.split |> S1C4.try_each


