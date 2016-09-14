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

  def aes_ecb_decrypt_block(key, data) do
    :crypto.block_decrypt(:aes_ecb, IO.iodata_to_binary(key), IO.iodata_to_binary(data))
    |> :binary.bin_to_list
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
    decrypted = fixed_xor(aes_ecb_decrypt_block(key, block), iv)
    if Enum.empty?(rest) do
      pkcs_unpad_block(decrypted)
    else
      decrypted ++ aes_cbc_decrypt(key, block, rest)
    end
  end

  def to_64(list), do: list |> IO.iodata_to_binary |> Base.encode64

  def fixed_xor(l1, l2), do: Enum.zip(l1, l2) |> Enum.map(fn({b1, b2}) -> b1 ^^^ b2 end)

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
      most ++ pkcs_unpad_block(last)
    else
      list
    end
  end
  def pkcs_unpad_block(list) do
    size = length(list)
    num = List.last(list)
    valid_num = num > 0 and num < size
    cond do
      valid_num and Enum.slice(list, size - num, num) == pkcs_padding(num) ->
        Enum.slice(list, 0, size - num)
      valid_num and num != 0xa and num != 0xd -> # Line Feeds / Carriage Returns are ok.
        IO.inspect {list, length(list)}
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

defmodule C2EX16 do
  @key CryptUtils.rand_bytes(16)
  @iv CryptUtils.rand_bytes(16)

  @prefix 'comment1=cooking%20MCs;userdata='
  @suffix ';comment2=%20like%20a%20pound%20of%20bacon'

  def enc(input) do
    CryptUtils.aes_cbc_encrypt(@key, @iv, @prefix ++ clean_input(input) ++ @suffix)
  end
  def dec(ctext), do: CryptUtils.aes_cbc_decrypt(@key, @iv, ctext)

  def parse_vals(list) do
    list
    |> Enum.chunk_by(&(&1 == ?;))
    |> Enum.reduce(%{}, fn(part, map) ->
      if part == ';' do
        map
      else
        case Enum.chunk_by(part, &(&1 == ?=)) do
          [k, '=', v] -> Map.put(map, k, v)
          [k]         -> Map.put(map, k, nil)
          _           -> map
        end
      end
    end)
  end

  # Just to test it cannot be done w/ just input.
  def try_admin(input) do
    vals = enc(input) |> dec |> parse_vals
    vals['admin'] == 'true'
  end

  def clean_input(input) do
    Enum.flat_map input, fn(c) ->
      case c do
        ?; -> '%3B'
        ?= -> '%3D'
        _ -> [c]
      end
    end
  end
end

# iv = for _ <- 1..16, do: 0
# key = 'YELLOW SUBMARINE'
# ptx = 'AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB'

# enc = CryptUtils.aes_cbc_encrypt(key, iv, ptx)
# IO.inspect Enum.chunk(enc, 16)

# [first | rest] = enc
# new_enc = [first ^^^ 23 | rest]

# IO.inspect CryptUtils.aes_cbc_decrypt(key, iv, new_enc) |> Enum.chunk(16)

# IO.inspect C2EX16.parse_vals('cats')
# IO.inspect C2EX16.parse_vals('cats=frogs')
# IO.inspect C2EX16.parse_vals('cats=frogs;snow;morsels=weevil')

# IO.inspect C2EX16.enc(';admin=true;') |> C2EX16.dec
IO.inspect(C2EX16.try_admin(';admin=true;'))

{blocksize, secret_size} = CryptUtils.determine_blocksize(&C2EX16.enc/1)
prefix_size = 32 # I guess we just know this?

input = CryptUtils.const_bytes(blocksize, ?A) ++ 'AAAAAadminAtrueA'


enc = C2EX16.enc(input)

# IO.inspect {input, length(input), length(enc)}

block_to_fix = Enum.slice(enc, prefix_size, blocksize)

fixed_block = List.replace_at(block_to_fix, 4, Enum.at(block_to_fix, 4) ^^^ (?A ^^^ ?;))
|> List.replace_at(10, Enum.at(block_to_fix, 10) ^^^ (?A ^^^ ?=))
|> List.replace_at(15, Enum.at(block_to_fix, 15) ^^^ (?A ^^^ ?;))


fixed = Enum.slice(enc, 0, prefix_size) ++ fixed_block ++
        Enum.slice(enc, (prefix_size + blocksize)..length(enc))

dec = C2EX16.dec(fixed)

IO.inspect {length(dec), Enum.chunk(dec, blocksize)}
IO.inspect C2EX16.parse_vals(dec)['admin'] == 'true'
