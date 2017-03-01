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

  def intermediates(msg, init \\ @init) do
    pad(msg)
    |> Enum.chunk(@size)
    |> Enum.map_reduce(init, fn(b, hsh)->
      next = c(b, hsh)
      {next, next}
    end)
    |> elem(0)
  end

  def c(block, hash) do
    n = Process.get(:hash_c) + 1
    Process.put(:hash_c, n)
    if rem(n, :math.pow(2, @size * 8) |> round) == 0, do: IO.puts "Passed #{n} hash compresses."

    :crypto.stream_init(:rc4, hash)
    |> :crypto.stream_encrypt(block)
    |> elem(1)
    |> :binary.bin_to_list
  end

  def pad(msg), do: CryptUtils.hash_pad(msg, @size)
end

defmodule ExMsg do
  @payload "Bam!Bam!"

  def build_msgs(k), do: build_msgs(k - 1, [], Hash.init)
  def build_msgs(-1, accum, _prev_h), do: Enum.reverse(accum)
  def build_msgs(k, accum, prev_h) do
    msgB = dummy_blocks(:math.pow(2, k) |> round)
    initB = Hash.hash_blocks(msgB, prev_h)
    {{msgA, extraB}, hsh} = find_match(prev_h, initB)

    build_msgs(k - 1, [{{msgA, msgB ++ [extraB]}, hsh} | accum], hsh)
  end

  def find_match(initA, initB, triesA \\ %{}, triesB \\ %{}) do
    a = rand_block
    b = rand_block
    hA = Hash.c(a, initA)
    hB = Hash.c(b, initB)
    triesA = Map.put(triesA, hA, a)
    found = triesA[hB]
    if found do
      {{found, b}, hB}
    else
      find_match(initA, initB, triesA, Map.put(triesB, hB, b))
    end
  end

  def find_glue(init, intms, min) do
    block = rand_block
    hsh = Hash.c(block, init)
    idx = intms[hsh]
    if idx && idx > min, do: {block, idx}, else: find_glue(init, intms, min)
  end

  def preimage(msg) do
    len = ceil(length(msg) / Hash.size)
    k = :math.log2(len) |> ceil

    ex_msg = build_msgs(k)
    final = List.last(ex_msg) |> elem(1)

    itms = Hash.intermediates(msg)
    |> Enum.with_index
    |> Enum.reduce(%{}, fn({h, idx}, m) -> Map.put(m, h, idx) end)

    {glue_block, glue_offset} = find_glue(final, itms, k + 1)

    prefix = build_prefix(ex_msg, glue_offset)
    rest = Enum.slice(msg, ((glue_offset + 1) * Hash.size)..-1)

    prefix ++ glue_block ++ rest
  end

  def build_prefix(ex_msg, len, accum \\ [])
  def build_prefix([], _, accum), do: List.flatten(accum)
  def build_prefix([{{short, long}, _hsh} | rest], len, accum) do
    to_use = if (length(rest) + length(long) + length(accum)) <= len, do: long, else: [short]
    build_prefix(rest, len, accum ++ to_use)
  end

  def dummy_blocks(n) do
    String.duplicate(@payload, ceil((n * Hash.size) / byte_size(@payload)))
    |> :binary.bin_to_list
    |> Enum.slice(0..(n * Hash.size))
    |> Enum.chunk(Hash.size)
  end

  def rand_block, do: CryptUtils.rand_bytes(Hash.size)

  def ceil(n), do: Float.ceil(n) |> round
end

msg = for _ <- 1..20 do
  'As regards clearness, the reader has a right to demand, in the first
place, discursive or logical clearness, that is, on the basis of
conceptions, and, secondly, intuitive or aesthetic clearness, by means
of intuitions, that is, by examples or other modes of illustration
in concreto. I have done what I could for the first kind of
intelligibility. This was essential to my purpose; and it thus became
the accidental cause of my inability to do complete justice to the
second requirement. I have been almost always at a loss, during the
progress of this work, how to settle this question. '
end
|> List.flatten


preimg = ExMsg.preimage(msg)
IO.puts ""
IO.puts preimg
IO.puts ""
IO.inspect ["Length Match:", length(msg), length(preimg), length(msg)== length(preimg)]
IO.inspect ["Hash Match:",
            Hash.hash(msg), Hash.hash(preimg),
            Hash.hash(msg) == Hash.hash(preimg)]

IO.puts "
Totals
  Hashes:                 #{Process.get(:hash)}
  Hash compress function: #{Process.get(:hash_c)} | #{:math.log2(Process.get(:hash_c))}
"
