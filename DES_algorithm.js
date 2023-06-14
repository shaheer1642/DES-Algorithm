
const text = "Hello";
const key = "abcdef"
console.log(`Plain Text:`, text)
console.log(`Key:`, key)

if (textToBinary(text).length > 64) throw Error('Text is too long')
const [binaryText, paddedZeros] = padBinary0s(textToBinary(text), 64, true)

if (textToBinary(key).length > 64) throw Error('Key is too long')
const binaryKey = padBinary0s(textToBinary(key), 64)

/* Encryption */
console.log('****************** Performing Encryption ******************')
const cipherText = DESRounds(binaryText, binaryKey)

/* Decryption */
console.log('****************** Performing Decryption ******************')
const plainText = DESRounds(cipherText, binaryKey, true)

console.log('')
console.log(`cipherText:`, binaryToText(cipherText))
console.log('')
console.log(`cipherText Binary (${cipherText.length}-bits):`, beautifyBinary(cipherText))
console.log(`cipherText HEX (${cipherText.length}-bits):`, parseInt(cipherText,2).toString(16))
console.log(`plainText:`, binaryToText(plainText.replace("0".repeat(paddedZeros),"")))
console.log(`plainText Binary (${plainText.length}-bits):`, beautifyBinary(plainText))
console.log(`plainText HEX (${plainText.length}-bits):`, parseInt(plainText,2).toString(16))

function DESRounds(message,key,decrypt) {
    const MPermutated = reArrangeBinary(
        message,
        [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]
    )
    console.log(`MPermutated (${MPermutated.length}-bits)`, beautifyBinary(MPermutated))

    const ML = splitBinary(MPermutated)[0]
    const MR = splitBinary(MPermutated)[1]
    console.log(`L0 (${ML.length}-bits):`, beautifyBinary(ML))
    console.log(`R0 (${MR.length}-bits):`, beautifyBinary(MR))

    const MLs = [ML]
    const MRs = [MR]
    const keys = generateKeys(key)

    for (let i = 0; i < 16; i++) {
        console.log(`****************** Round ${i+1} ******************`)
        const MRExpanded = expansion(MRs[i])
        
        console.log(`MR Expanded (${MRExpanded.length}-bits):`, beautifyBinary(MRExpanded))
        
        // XOR with key
        const subkey = keys[decrypt ? 15 - i : i]
        console.log(`Subkey (${subkey.length}-bits):`, beautifyBinary(subkey))
        const MRXORSUBKEY = bitwiseXOR(MRExpanded, subkey)
        console.log(`MR XOR Subkey (${MRXORSUBKEY.length}-bits):`, beautifyBinary(MRXORSUBKEY))
        
        const MRSubstituted = substituteBinary(MRXORSUBKEY)
        console.log(`MR Substituted (${MRSubstituted.length}-bits):`, beautifyBinary(MRSubstituted))
        
        const MRPermutated = reArrangeBinary(MRSubstituted, 
            [
                16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25
            ]
        )
        console.log(`MR Permutated (${MRPermutated.length}-bits):`, beautifyBinary(MRPermutated))
        
        const MRXORML = bitwiseXOR(MRPermutated, MLs[i])
        console.log(`MR XOR ML (${MRXORML.length}-bits):`, beautifyBinary(MRXORML))

        const newML = MRs[i]
        const newMR = MRXORML
        MLs.push(newML)
        MRs.push(newMR)

        console.log(`L${i+1} (${newML.length}-bits):`, beautifyBinary(newML))
        console.log(`R${i+1} (${newMR.length}-bits):`, beautifyBinary(newMR))
    }

    const L16 = MLs[16]
    const R16 = MRs[16]

    const MFinalPermutation = reArrangeBinary(
        `${R16}${L16}`, 
        [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]
    )

    return MFinalPermutation
}

function generateKeys(key) {

    const KeyPermutated = reArrangeBinary(
        key,
        [
            57, 49, 41, 33, 25, 17, 9, 1,
            58, 50, 42, 34, 26, 18, 10, 2,
            59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39,
            31, 23, 15, 7, 62, 54, 46, 38,
            30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4
        ]
    )
    console.log(`Key Permutated (${KeyPermutated.length}-bits):`, beautifyBinary(KeyPermutated))
    const KeyC = splitBinary(KeyPermutated)[0]
    const KeyD = splitBinary(KeyPermutated)[1]
    console.log(`C (${KeyC.length}-bits):`, KeyC)
    console.log(`D (${KeyD.length}-bits):`, KeyD)

    const subkeysC = [KeyC]
    const subkeysD = [KeyD]
    const shiftBy = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    for (let i = 1; i < 17; i++) {
        subkeysC.push(leftShiftBinary(subkeysC[i-1], shiftBy[i-1]))
        subkeysD.push(leftShiftBinary(subkeysD[i-1], shiftBy[i-1]))
    }
    const keys = []
    for (let i = 0; i < 16; i++) {
        keys.push(reArrangeBinary(
            `${subkeysC[i+1]}${subkeysD[i+1]}`,
            [
                14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32
            ]
        ))
    }
    return keys
}

function bitwiseXOR(binary1, binary2) {
    if (binary1.length != binary2.length) throw Error('Length mismatch')
    var result = []
    for (let i = 0; i < binary1.length; i++) {
        result.push(
            binary1[i] == 1 && binary2[i] == 1 ? 0 :
            binary1[i] == 0 && binary2[i] == 0 ? 0 :
            binary1[i] == 1 && binary2[i] == 0 ? 1 :
            binary1[i] == 0 && binary2[i] == 1 ? 1 : undefined
        )
    }
    return result.join('')
}

function leftShiftBinary(binary, shift_by) {
    const arr = binary.split('')
    const shifted_arr = []

    arr.map((char,index) => {
        var n_index = (index - shift_by) % arr.length
        if (n_index < 0) n_index = arr.length + n_index
        shifted_arr[n_index] = char
    })
    return shifted_arr.join('')
}

function textToBinary(text) {
    return text.split('').map(c => c.charCodeAt(0).toString(2)).join('')
}

function binaryToText(binary) {
    return binary.replace(/(.{7})/g,"$1$").replaceAll("$",' ').trim().split(' ').map(block => String.fromCharCode(parseInt(block, 2))).join('')
}

function padBinary0s(binary, final_length, paddedZeros) {
    if (!final_length) throw Error('final_length not defined')
    if(binary.length >= final_length) return binary
    var zeroesAdded = 0
    while(binary.length != final_length) {
        binary = 0 + binary
        zeroesAdded++
    }
    if (paddedZeros) return [binary, zeroesAdded]
    else return binary
}

function splitBinary(binary) {
    return [
        binary.substring(0,binary.length / 2),
        binary.substring(binary.length / 2, binary.length),
    ]
}

function expansion(binary) {
    const pBox = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]
    return reArrangeBinary(binary,pBox)
}

function reArrangeBinary(binary, pBox) {
    const reArrangedBinary = []
    pBox.forEach(index => reArrangedBinary.push(binary[index -1]))
    return(reArrangedBinary.join(''))
}

function substituteBinary(binary) {
    const subBox = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    binary = binary.replace(/(.{6})/g, "$1$").replaceAll("$", ' ').trim()
    const substituted_binary = []
    binary.split(' ').forEach((block,index) => {
        const sub = padBinary0s((subBox[index][parseInt(`${block[0]}${block[5]}`, 2)][parseInt(`${block.substring(1, 5)}`, 2)]).toString(2),4)
        substituted_binary.push(sub)
    })
    return substituted_binary.join('')
}

function beautifyBinary(binary) {
    return binary.replace(/(.{4})/g,"$1$").replaceAll("$",' ').trim()
}