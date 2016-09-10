use Bitwise

defmodule S2C11 do
  def encryption_oracle(data) do
    prefix = rand_bytes(:rand.uniform(6) + 4)
    suffix = rand_bytes(:rand.uniform(6) + 4)
    key = rand_bytes(16)
    full_data = prefix ++ data ++ suffix
    if :rand.uniform(2) > 1 do
      {"ecb", aes_ecb_encrypt(key, full_data)}
    else
      {"cbc", aes_cbc_encrypt(key, rand_bytes(16), full_data)}
    end
  end

  def rand_bytes(n) do
    for _ <- 1..n, do: :rand.uniform(0xff + 1) - 1
  end

  def aes_cbc_encrypt(_key, _iv, []), do: []
  def aes_cbc_encrypt(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    encrypted = aes_ecb_encrypt(key, fixed_xor(iv, pkcs_pad(block, size)))
    encrypted ++ aes_cbc_encrypt(key, encrypted, rest)
  end

  def aes_cbc_decrypt(key, iv, data) do
    size = length(key)
    {block, rest} = Enum.split(data, size)
    decrypted = fixed_xor(aes_ecb_decrypt(key, block), iv)
    if Enum.empty?(rest) do
      pkcs_unpad(decrypted)
    else
      decrypted ++ aes_cbc_decrypt(key, block, rest)
    end
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

  def read_64(path) do
    path
    |> File.read!
    |> Base.decode64!(ignore: :whitespace)
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

  def count_repeats(line, chunk_size) do
    count_repeats Enum.chunk(line, chunk_size)
  end
  def count_repeats([]) do
    0
  end
  def count_repeats([chunk | rest]) do
    Enum.count(rest, &(&1 == chunk)) + count_repeats(rest)
  end
end


input = for _ <- 1..64, do: ?a
IO.inspect input

for _ <- 1..50 do
  {type, out} = S2C11.encryption_oracle(input)
  detected = if S2C11.count_repeats(out, 16) > 0, do: "ecb", else: "cbc"
 IO.inspect [type == detected, type, detected]
end

