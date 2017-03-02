defmodule CryptUtils do
  def const_bytes(0, _b), do: []
  def const_bytes(n, b), do: (for _ <- 1..n, do: b)

  def rand_bytes(n), do: (for _ <- 1..n, do: :crypto.rand_uniform(1, 0xff))

  def hash_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    length_bytes = length(list) |> Integer.digits(256)
    zeros = blocksize - last_size - length(length_bytes)
    zeros = if zeros < 0, do: zeros + blocksize, else: zeros
    list ++ const_bytes(zeros, 0) ++ length_bytes
  end
end

Process.put(:hash, 0)
Process.put(:hash_c, 0)
Process.put(:hash_before, 0)
Process.put(:hash_after, 0)
Process.put(:hash_state, :hash_before)
defmodule Hash do
  @size 4
  @init CryptUtils.rand_bytes(@size)
  @input_pad CryptUtils.const_bytes(16 - @size, 0)

  def size, do: @size
  def init, do: @init

  def hash(msg, init \\ @init) do
    pad(msg) |> Enum.chunk(@size) |> hash_blocks(init)
  end

  def hash_blocks(blocks, init \\ @init) do
    Process.put(:hash, Process.get(:hash) + 1)
    Enum.reduce(blocks, init, &c/2)
  end

  def c(block, hash) do
    n = Process.get(:hash_c) + 1
    Process.put(:hash_c, n)
    Process.put(Process.get(:hash_state), Process.get(Process.get(:hash_state)) + 1)
    if rem(n, :math.pow(2, @size * 8) |> round) == 0, do: IO.puts "Passed #{n} hash compresses."

    :crypto.stream_init(:rc4, hash)
    |> :crypto.stream_encrypt(block)
    |> elem(1)
    |> :binary.bin_to_list
  end

  def pad(msg), do: CryptUtils.hash_pad(msg, @size)
end

defmodule N do
  defstruct [:msgA, :msgB, :initA, :initB, :hsh]
end

defmodule NostryD do
  @prediction ' Space travel is bunk.  '

  def build_tree(k) do
    pair_states(init_states(k))
  end

  def pair_states(states), do: pair_states(states, [states])
  def pair_states(states, accum) when length(states) <= 1, do: Enum.reverse(accum)
  def pair_states(states, accum) do
    reduced = Enum.chunk(states, 2) |> Enum.map(fn([sA, sB]) -> find_match(sA.hsh, sB.hsh) end)
    pair_states(reduced, [reduced | accum])
  end

  def init_states(k) do
    for _ <- 1..pow(2, k) do
      blk = rand_block
      init = rand_block
      %N{
        msgA: blk,
        msgB: blk,
        initA: init,
        initB: init,
        hsh: Hash.c(blk, init)
       }
    end
  end

  def find_match(initA, initB, triesA \\ %{}, triesB \\ %{}) do
    a = rand_block
    b = rand_block
    hA = Hash.c(a, initA)
    hB = Hash.c(b, initB)
    triesA = Map.put(triesA, hA, a)
    found = triesA[hB]
    if found do
      %N{
        msgA: found,
        msgB: b,
        initA: initA,
        initB: initB,
        hsh: hB
       }
    else
      find_match(initA, initB, triesA, Map.put(triesB, hB, b))
    end
  end

  def pred_hash(tree) do
    [%{hsh: hsh}] = List.last(tree)
    l_bytes = (length(tree) * Hash.size + length(@prediction) + Hash.size)
              |> Integer.digits(256)
    Hash.c(CryptUtils.const_bytes(Hash.size - length(l_bytes), 0) ++ l_bytes, hsh)
  end

  def pred_msg(tree) do
    hsh = Enum.chunk(@prediction, Hash.size) |> Hash.hash_blocks
    leaves = hd(tree) |> Enum.map(&(&1.initA))
    {glue_block, leaf_init} = find_glue(hsh, leaves)
    @prediction ++ glue_block ++ build_suffix(tree, leaf_init)
  end

  def find_glue(init, leaves) do
    block = rand_block
    hsh = Hash.c(block, init)
    if Enum.member?(leaves, hsh), do: {block, hsh}, else: find_glue(init, leaves)
  end

  def build_suffix(tree, last_h, accum \\ '')
  def build_suffix([], _last_h, accum), do: accum
  def build_suffix([nodes | rest], last_h, accum) do
    n = Enum.find(nodes, &(&1.initA == last_h || &1.initB == last_h))
    msg = if n.initA == last_h, do: n.msgA, else: n.msgB
    build_suffix(rest, n.hsh, accum ++ msg)
  end

  def rand_block, do: CryptUtils.rand_bytes(Hash.size)

  def pow(b, e), do: :math.pow(b, e) |> round
  def ceil(n), do: Float.ceil(n) |> round
end

tree = NostryD.build_tree(6)
pred_hash = NostryD.pred_hash(tree)

Process.put(:hash_state, :hash_after)
msg = NostryD.pred_msg(tree)

IO.puts "---"
IO.puts msg
IO.puts "---"
IO.inspect ['Hash Matches?',
            pred_hash, Hash.hash(msg),
            pred_hash == Hash.hash(msg)]

IO.puts "
Totals
  Hashes:                 #{Process.get(:hash)}
  Hash compress function: #{Process.get(:hash_c)} | #{:math.log2(Process.get(:hash_c))}
  Tree Build:             #{Process.get(:hash_before)} | #{:math.log2(Process.get(:hash_before))}
  Compose Prediction:     #{Process.get(:hash_after)} | #{:math.log2(Process.get(:hash_after))}
"
