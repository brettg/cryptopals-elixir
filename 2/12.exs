use Bitwise

defmodule RandBytes do
  def rand_bytes(n) do
    for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1
  end
end

defmodule S2C12 do
  @key RandBytes.rand_bytes(16)
  @secret "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"
|> Base.decode64!(ignore: :whitespace)
|> :binary.bin_to_list

  def encryption_oracle(data) do
    full_data = data ++ @secret
    aes_ecb_encrypt(@key, full_data)
  end

  def aes_ecb_encrypt(key, data) do
    :crypto.block_encrypt(:aes_ecb, IO.iodata_to_binary(key),
                                    IO.iodata_to_binary(pkcs_pad(data, length(key))))
    |> :binary.bin_to_list
  end

  def aes_ecb_decrypt(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
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
      num = blocksize - last_size
      list ++ for _ <- 1..num, do: num
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

  def pkcs_padding(num) do
    for _ <- 1..num, do: num
  end

  def count_repeats(line, chunk_size), do: count_repeats Enum.chunk(line, chunk_size)
  def count_repeats([]), do: 0
  def count_repeats([chunk | rest]) do
    Enum.count(rest, &(&1 == chunk)) + count_repeats(rest)
  end

  def determine_blocksize do
    determine_blocksize('A', length(encryption_oracle('A')))
  end
  def determine_blocksize(last, last_size) do
    next = last ++ 'A'
    size = length(encryption_oracle(next))
    if size > last_size do
      {size - last_size, last_size - length(last)}
    else
      determine_blocksize(next, size)
    end
  end

  def make_dictionary(base) do
    blocksize = length(base) + 1
    Enum.reduce(0..255, %{}, fn(n, map) ->
      Map.put(map, encryption_oracle(base ++ [n]) |> Enum.slice(0, blocksize), n)
    end)
  end

  def solve_next_char(solved, blocksize) do
   solved_len = length(solved)

   solve_fill =  Enum.take(solved, - (blocksize - 1))
   dict_fill = const_list(blocksize - length(solve_fill) - 1) ++ solve_fill
   dict = make_dictionary(dict_fill)


   block_num = div(length(solved), blocksize) + 1
   offset_fill_n = blocksize - rem(solved_len, blocksize) - 1
   to_encrypt = const_list(blocksize) ++ const_list(offset_fill_n)
   enc = encryption_oracle(to_encrypt)

   block = Enum.slice(enc, block_num * blocksize, blocksize)
   dict[block]
  end

  def solve_secret(blocksize, secret_size), do: solve_secret(blocksize, secret_size, '', 0)
  def solve_secret(_blocksize, secret_size, _prev, secret_size), do: []
  def solve_secret(blocksize, secret_size, prev, offset) do
    next_char = [solve_next_char(prev, blocksize)]
    next_char ++ solve_secret(blocksize, secret_size, prev ++ next_char, offset + 1)
  end

  def const_list(0), do: []
  def const_list(len) do
    for _ <- 1..len, do: ?A
  end
end

{blocksize, secret_size} = S2C12.determine_blocksize

a_block = for _ <- 1..blocksize, do: 'A'
is_ecb = S2C12.count_repeats(S2C12.encryption_oracle(a_block ++ a_block ++ a_block)) > 0
IO.inspect [blocksize, secret_size, is_ecb]

IO.inspect S2C12.solve_secret(blocksize, secret_size)
