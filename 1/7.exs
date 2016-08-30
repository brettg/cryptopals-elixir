
key = "YELLOW SUBMARINE"

path = "7.txt"
data = path
|> File.read!
|> String.split
|> Enum.join
|> Base.decode64!(ignore: :whitespace)

IO.inspect data

out = :crypto.block_decrypt(:aes_ecb, key, data)
IO.puts out <> ""
