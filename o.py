class SDES:
    # Classe que implementa o algoritmo Simplified DES (S-DES).
    # O método __init__ inicializa as tabelas de permutação, as S-Boxes e gera as subchaves (K1 e K2) com base na chave principal de 10 bits.
    def __init__(self, key):
        self.key = key
        self.P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
        self.P8 = [6, 3, 7, 4, 8, 5, 10, 9]
        self.IP = [2, 6, 3, 1, 4, 8, 5, 7]
        self.IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
        self.EP = [4, 1, 2, 3, 2, 3, 4, 1]
        self.P4 = [2, 4, 3, 1]
        self.S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
        self.S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]
        self.K1, self.K2 = self.generate_keys()

    def permute(self, sequence, table):
        # Realiza uma permutação dos bits de acordo com a tabela fornecida.
        # Esse método é usado em várias etapas do algoritmo S-DES, incluindo
        # a geração de subchaves (P10, P8) e as permutações iniciais e finais (IP, IP_INV).
        return [sequence[i-1] for i in table]

    def left_shift(self, half, shifts):
        # Realiza um deslocamento circular para a esquerda em uma metade da chave.
        # Esse método é usado na geração de subchaves para deslocar os bits das
        # duas metades da chave de 10 bits antes de aplicar as permutações.
        return half[shifts:] + half[:shifts]

    def generate_keys(self):
        # Gera as duas subchaves K1 e K2 a partir da chave principal de 10 bits.

        # 1. Permutação P10: Reorganiza os bits da chave conforme a tabela P10.
        key = self.permute(self.key, self.P10)

        # 2. Divisão em duas metades (5 bits cada):
        left, right = key[:5], key[5:]

        # 3. Deslocamento circular de 1 posição em ambas as metades.
        left, right = self.left_shift(left, 1), self.left_shift(right, 1)

        # 4. Permutação P8: Combina as duas metades e seleciona 8 bits para formar K1.
        K1 = self.permute(left + right, self.P8)

        # 5. Deslocamento circular de 2 posições em ambas as metades.
        left, right = self.left_shift(left, 2), self.left_shift(right, 2)

        # 6. Permutação P8: Combina as duas metades novamente e seleciona 8 bits para formar K2.
        K2 = self.permute(left + right, self.P8)

        # Retorna as subchaves geradas.
        return K1, K2

    def sbox(self, half, sbox):
        # Traduz a entrada de 4 bits em uma saída de 2 bits usando a tabela S-Box fornecida.
        # 1. Determina a linha na S-Box usando o primeiro e o último bit da entrada (half).
        row = (half[0] << 1) + half[3]
        # 2. Determina a coluna na S-Box usando os bits do meio da entrada (half).
        col = (half[1] << 1) + half[2]
        # 3. Obtém o valor correspondente na S-Box para a linha e coluna calculadas.
        value = sbox[row][col]
        # 4. Converte o valor decimal obtido em uma lista de 2 bits binários e retorna.
        return [int(x) for x in f"{value:02b}"]

    def feistel(self, half, subkey):
        # Combina a metade direita do bloco de dados com a subchave fornecida e aplica as operações Feistel.
        # 1. Expansão e permutação: Expande a entrada de 4 bits para 8 bits usando a tabela EP.
        expanded = self.permute(half, self.EP)
        # 2. XOR: Combina os 8 bits expandidos com a subchave usando a operação XOR.
        xor_result = [expanded[i] ^ subkey[i] for i in range(8)]
        # 3. S-Boxes: Divide o resultado XOR em duas metades de 4 bits e aplica as S-Boxes (S0 e S1).
        left, right = xor_result[:4], xor_result[4:]
        sbox_output = self.sbox(left, self.S0) + self.sbox(right, self.S1)
        # 4. Permutação P4: Reorganiza os 4 bits resultantes das S-Boxes.
        return self.permute(sbox_output, self.P4)

    def encrypt(self, plaintext):
        data = self.permute(plaintext, self.IP)
        left, right = data[:4], data[4:]
        # Round 1
        temp = right
        left = [left[i] ^ bit for i, bit in enumerate(self.feistel(right, self.K1))]
        right = left
        left = temp
        # Round 2
        left = [left[i] ^ bit for i, bit in enumerate(self.feistel(right, self.K2))]
        return self.permute(left + right, self.IP_INV)

    def decrypt(self, ciphertext):
        # Decifra o texto cifrado revertendo o processo de cifragem.
        # Utiliza as subchaves em ordem inversa: primeiro K2 e depois K1.
        data = self.permute(ciphertext, self.IP)
        left, right = data[:4], data[4:]
        # Round 1 (usando K2)
        temp = right
        left = [left[i] ^ bit for i, bit in enumerate(self.feistel(right, self.K2))]
        right = left
        left = temp
        # Round 2 (usando K1)
        left = [left[i] ^ bit for i, bit in enumerate(self.feistel(right, self.K1))]
        return self.permute(left + right, self.IP_INV)

# Exemplo de uso:
# Chave de 10 bits e texto claro de 8 bits
key = [1,0,1,0,0,0,0,0,1,0]
plaintext = [1,1,0,1,0,1,1,1]
sdes = SDES(key)
ciphertext = sdes.encrypt(plaintext)
decrypted = sdes.decrypt(ciphertext)

print("Texto cifrado:", ciphertext)
print("Texto decifrado:", decrypted)
