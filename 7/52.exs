defmodule CryptUtils do
  def const_bytes(0, _b), do: []
  def const_bytes(n, b), do: (for _ <- 1..n, do: b)

  def rand_bytes(n), do: (for _ <- 1..n, do: :crypto.rand_uniform(1, 0xff))

  def hash_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    zeros = blocksize - last_size
    list ++ const_bytes(zeros, 0)
  end
end

Process.put(:hash_f, 0)
defmodule HashF do
  @init CryptUtils.rand_bytes(2)
  @input_pad CryptUtils.const_bytes(14, 0)

  def init, do: @init

  def hash(msg, hash \\ @init) do
    Process.put(:hash_f, Process.get(:hash_f) + 1)

    pad(msg)
    |> Enum.chunk(2)
    |> Enum.reduce(hash, &c/2)
  end

  def pad(msg), do: CryptUtils.hash_pad(msg, 2)

  defp c(block, hash) do
    :crypto.block_encrypt(:aes_ecb, hash ++ @input_pad, block ++ @input_pad)
    |> :binary.bin_to_list
    |> Enum.slice(0..1)
  end
end

Process.put(:hash_g, 0)
defmodule HashG do
  @size 4
  @init CryptUtils.rand_bytes(@size)
  @input_pad CryptUtils.const_bytes(16 - @size, 0)

  def init, do: @init

  def hash(msg, hash \\ @init) do
    Process.put(:hash_g, Process.get(:hash_g) + 1)

    pad(msg)
    |> Enum.chunk(@size)
    |> Enum.reduce(hash, &c/2)
  end

  def pad(msg), do: CryptUtils.hash_pad(msg, @size)

  defp c(block, hash) do
    :crypto.block_encrypt(:aes_ecb, hash ++ @input_pad, block ++ @input_pad)
    |> :binary.bin_to_list
    |> Enum.slice(0..(@size - 1))
  end
end

Process.put(:hash_h, 0)
defmodule HashH do
  def hash(msg) do
    Process.put(:hash_h, Process.get(:hash_h) + 1)
    HashF.hash(msg) ++ HashG.hash(msg)
  end
end

defmodule Collider do
  def find_f(init, tried \\ %{}) do
    msg = CryptUtils.rand_bytes(4)
    hsh = HashF.hash(msg, init)
    if tried[hsh] do
      {{msg, tried[hsh]}, hsh}
    else
      find_f(init, Map.put(tried, hsh, msg))
    end
  end

  def find_f_n(n), do: find_f_n(n, HashF.init, [])
  def find_f_n(0, _init, found), do: build_combos(found)
  def find_f_n(n, init, found) do
    {pair, hsh} = find_f(init)
    find_f_n(n - 1, hsh, [pair | found])
  end

  defp build_combos([{a, b} | rest]), do: build_combos(rest, [a, b])
  defp build_combos([], accum), do: accum
  defp build_combos([{a, b} | rest], accum) do
    build_combos(rest, prefix_all(accum, HashF.pad(a)) ++ prefix_all(accum, HashF.pad(b)))
  end

  defp prefix_all(l, prefix, accum \\ [])
  defp prefix_all([], _prefix, accum), do: accum
  defp prefix_all([suffix | rest], prefix, accum) do
    prefix_all(rest, prefix, [(prefix ++ suffix) | accum])
  end


  def find_g(candidates, tried \\ %{})
  def find_g([], _), do: nil
  def find_g([cand | rest], tried) do
    hsh = HashG.hash(cand)
    if tried[hsh] do
      {{cand, tried[hsh]}, hsh}
    else
      find_g(rest, Map.put(tried, hsh, cand))
    end
  end

  def find_h, do: (find_f_n(16) |> find_g) || find_h
end

{{a, b}, _g_hsh} = Collider.find_h
IO.inspect [a, b,
            HashH.hash(a), HashH.hash(b),
            HashH.hash(a) == HashH.hash(b)]

IO.puts "
Total hashes:
  HashF: #{Process.get(:hash_f)}
  HashG: #{Process.get(:hash_g)}
  HashH: #{Process.get(:hash_h)}
  Total: #{Process.get(:hash_f) + Process.get(:hash_g) + Process.get(:hash_h)}
"
