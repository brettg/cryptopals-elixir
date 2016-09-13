use Bitwise

defmodule CryptUtils do
  def aes_ecb_encrypt(key, data) do
    :crypto.block_encrypt(:aes_ecb, IO.iodata_to_binary(key),
                                    IO.iodata_to_binary(pkcs_pad(data, length(key))))
    |> :binary.bin_to_list
  end

  def aes_ecb_decrypt(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
    |> pkcs_unpad(length(key))
  end

  def to_64(list) do
    list |> IO.iodata_to_binary |> Base.encode64
  end

  def fixed_xor(l1, l2) do
    Enum.zip(l1, l2)
    |> Enum.map(fn ({n1, n2}) -> n1 ^^^ n2 end)
  end

  def pkcs_pad(list, blocksize) do
    last_size = rem(length(list), blocksize)
    if last_size != 0 do
      list ++ pkcs_padding(blocksize - last_size)
    else
      list
    end
  end

  def pkcs_unpad(list, blocksize) do
    lb_size = rem(length(list), blocksize)
    if lb_size == 0 do
      {most, last} = Enum.split(list, length(list) - blocksize)
      most ++ pkcs_unpad(last)
    else
      list
    end
  end
  def pkcs_unpad(list) do
    size = length(list)
    num = List.last(list)
    if num > 0 and num < size and Enum.slice(list, size - num, num) == pkcs_padding(num) do
      Enum.slice(list, 0, size - num)
    else
      list
    end
  end

  def pkcs_padding(n), do: (for _ <- 1..n, do: n)
  def rand_bytes(n), do: (for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1)

  def const_bytes(0, _), do: []
  def const_bytes(n, byte), do: (for _ <- 1..n, do: byte)

  def determine_blocksize(enc_fn) do
    determine_blocksize(enc_fn, 'A', length(enc_fn.('A')))
  end
  def determine_blocksize(enc_fn, last, last_size) do
    next = last ++ 'A'
    size = length(enc_fn.(next))
    if size > last_size do
      {size - last_size, last_size - length(last)}
    else
      determine_blocksize(enc_fn, next, size)
    end
  end

  def determine_prefix_size(enc_fn, blocksize) do
    determine_prefix_size(enc_fn, blocksize, '')
  end
  def determine_prefix_size(enc_fn, blocksize, last) do
    next = last ++ 'A'
    if length(repeats = find_repeats(enc_fn.(next), blocksize)) > 0 do
      [{first_repeat, _} | _] = repeats
      blocksize * first_repeat - (length(next) - blocksize * 2)
    else
      determine_prefix_size(enc_fn, blocksize, next)
    end
  end

  def find_repeats(list, blocksize), do: find_repeats_from 0, Enum.chunk(list, blocksize)
  def find_repeats_from(_idx, []), do: []
  def find_repeats_from(idx, [chunk | rest]) do
    if next_idx = Enum.find_index(rest, &(&1 == chunk)) do
      [{idx, idx + next_idx + 1}] ++ find_repeats_from(idx + 1, rest)
    else
      find_repeats_from(idx + 1, rest)
    end
  end
end

defmodule S2C13 do
  @key CryptUtils.rand_bytes(16)
  @prefix  CryptUtils.rand_bytes(:rand.uniform(40))
  @secret 'This is the secret text. It is quite amazing. For you, at least.'

  def enc_oracle(list) do
    CryptUtils.aes_ecb_encrypt(@key, @prefix ++ list ++ @secret)
  end

  def solve_next_char(enc_fn, {blocksize, psize}, solved) do
   solved_len = length(solved)

   solve_fill = Enum.take(solved, -(blocksize - 1))
   dict_fill = CryptUtils.const_bytes(blocksize - length(solve_fill) - 1, ?A) ++ solve_fill
   dict = make_dictionary(enc_fn, dict_fill, psize)

   prefix_pad_n = blocksize - rem(psize, blocksize)
   offset_fill_n = blocksize - rem(solved_len, blocksize) - 1
   to_encrypt = CryptUtils.const_bytes(prefix_pad_n + blocksize + offset_fill_n, ?A)
   enc = enc_fn.(to_encrypt)

   block_num = (div(psize, blocksize) + 1) + (div(length(solved), blocksize) + 1)
   block = Enum.slice(enc, block_num * blocksize, blocksize)

   dict[block]
  end

  def solve_secret(enc_fn, sizes), do: solve_secret(enc_fn, sizes, '', 0)
  def solve_secret(_, {_, _, secret_size}, _, secret_size), do: []
  def solve_secret(enc_fn, {blocksize, psize, ssize}, prev, offset) do
    next_char = [solve_next_char(enc_fn, {blocksize, psize}, prev)]
    next_char ++ solve_secret(enc_fn, {blocksize, psize, ssize}, prev ++ next_char, offset + 1)
  end

  def make_dictionary(enc_fn, base, prefix_size) do
    blocksize = length(base) + 1
    prefix_pad = CryptUtils.const_bytes(blocksize - rem(prefix_size, blocksize), ?A)
    target_block = div(prefix_size, blocksize) + 1

    Enum.reduce(0..255, %{}, fn(n, map) ->
      Map.put(map, enc_fn.(prefix_pad ++ base ++ [n])
      |> Enum.slice(blocksize * target_block, blocksize), n)
    end)
  end
end

{blocksize, secret_size} = CryptUtils.determine_blocksize(&S2C13.enc_oracle/1)
prefix_size = CryptUtils.determine_prefix_size(&S2C13.enc_oracle/1, blocksize)

IO.inspect {blocksize, secret_size, prefix_size}
IO.inspect S2C13.solve_secret(&S2C13.enc_oracle/1, {blocksize, prefix_size, secret_size - prefix_size})
