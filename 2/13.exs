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
  @base_profile %{"id" => 10, "role" => "user"}

  def decode_profile(prof_string) do
    URI.decode_query(IO.iodata_to_binary(prof_string))
  end
  def encode_profile(map) do
    map
    |> Enum.map(fn({k, v}) -> "#{k}=#{v}" end)
    |> Enum.join("&")
  end

  def profile_for(email) do
    encode_profile(Map.merge(@base_profile, %{"email" => email}))
  end

  def encrypt_profile(email) do
    CryptUtils.aes_ecb_encrypt(@key, profile_for(IO.iodata_to_binary(email)) |> :binary.bin_to_list)
  end

  def decrypt_profile(ctext) do
    CryptUtils.aes_ecb_decrypt(@key, ctext) |> decode_profile
  end

  def decrypt(l) do
    CryptUtils.aes_ecb_decrypt(@key, l)
  end
end


# IO.puts(CryptUtils.pkcs_unpad('email=aaa&id=10&role=user\a\a\a\a\a\a\a'))
# IO.puts(S2C13.profile_for("aaa"))
# IO.inspect(S2C13.encrypt_profile("aaa"))
# IO.inspect(S2C13.decrypt_profile(S2C13.encrypt_profile("aaa")))

# Depends on knowledge of underlying serialization details, but that appears normal for exercise...

{blocksize, secret_size} = CryptUtils.determine_blocksize(&S2C13.encrypt_profile/1)
prefix_size = CryptUtils.determine_prefix_size(&S2C13.encrypt_profile/1, blocksize)

gen_admin_input = CryptUtils.const_bytes(blocksize - prefix_size, ?A) ++
                  CryptUtils.pkcs_pad('admin', blocksize)

admin_ctext = S2C13.encrypt_profile(gen_admin_input)
admin_block = Enum.slice(admin_ctext, (div(prefix_size, blocksize) + 1) * blocksize, blocksize)

len_needed = blocksize - rem(secret_size, blocksize) + length('user')
base_ctext = S2C13.encrypt_profile(CryptUtils.const_bytes(len_needed, ?A))
new_ctext = Enum.slice(base_ctext, 0, length(base_ctext) - blocksize) ++ admin_block

IO.inspect [len_needed, length(base_ctext), length(new_ctext)]

IO.inspect S2C13.decrypt_profile(new_ctext)
