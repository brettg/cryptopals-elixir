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
    valid_num = num > 0 and num < size
    cond do
      valid_num and Enum.slice(list, size - num, num) == pkcs_padding(num) ->
        Enum.slice(list, 0, size - num)
      valid_num and num != 0xa and num != 0xd -> # Line Feeds / Carriage Returns are ok.
        raise "Invalid PKCS7 Padding!"
      true ->
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

IO.inspect CryptUtils.pkcs_unpad('ABCDEFGHIJ' ++ [6, 6, 6, 6, 6, 6])
IO.inspect CryptUtils.pkcs_unpad('ABCDEFGHIJKLMNO\n')
IO.inspect CryptUtils.pkcs_unpad('ABCDEFGHIJKLMNO\r')

try do
  IO.inspect CryptUtils.pkcs_unpad('ABCDEFGHIJ' ++ [5, 6, 6, 6, 6, 6])
rescue
  _ -> IO.puts "Good"
end

try do
  IO.inspect CryptUtils.pkcs_unpad('ABCDEFGHIJ' ++ [7, 7, 7, 7, 7, 7])
rescue
  _ -> IO.puts "Good"
end
