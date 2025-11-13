<?php

/**
 * 使用PBKDF2算法从密码派生密钥
 *
 * @param string $password 输入密码
 * @param string $salt 加密盐值
 * @param int $iterations 迭代次数，增加计算复杂度
 * @param int $keyLength 期望生成的密钥长度(字节)
 * @param string $algorithm 哈希算法，默认为'sha256'
 * @return string 派生出的二进制密钥
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) 是一种密钥派生函数，
 * 通过重复哈希来增加暴力破解的难度，常用于密码存储和加密密钥生成。
 */
function pbkdf2($password, $salt, $iterations, $keyLength, $algorithm = 'sha256') {
    $hashLength = strlen(my_hash('', $algorithm,true));
    $blockCount = ceil($keyLength / $hashLength);

    $output = '';
    for ($i = 1; $i <= $blockCount; $i++) {
        $last = $salt . pack('N', $i);
        $last = $xorsum = my_hash_hmac($algorithm, $last, $password, true);
        for ($j = 1; $j < $iterations; $j++) {
            $xorsum ^= ($last = my_hash_hmac($algorithm, $last, $password, true));
        }
        $output .= $xorsum;
    }

    return substr($output, 0, $keyLength);
}
/**
 * 使用 openssl_digest 实现的哈希函数
 * @param string $data 要哈希的数据
 * @param string $algorithm 哈希算法 (默认: sha256)
 * @param bool $raw_output 是否返回原始二进制数据 (默认: false)
 * @return string 哈希结果
 */
function my_hash($data, $algorithm = 'sha256', $raw_output = false) {
    if($algorithm =='sm3'){
        // 如果你的PHP版本不支持sm3，请使用sm3的原生方法
        return  openssl_digest($data, $algorithm, $raw_output);
    }
    $digest = openssl_digest($data, $algorithm, $raw_output);
    if ($digest === false) {
        throw new RuntimeException("OpenSSL digest failed for algorithm: $algorithm");
    }
    return $digest;
}

/**
 * 使用原生PHP方法实现的HMAC哈希函数
 * @param string $algo 哈希算法 (如: sha256, md5等)
 * @param string $data 要哈希的数据
 * @param string $key 加密密钥
 * @param bool $raw_output 是否返回原始二进制数据 (默认: false)
 * @return string HMAC哈希结果
 */
function my_hash_hmac($algo, $data, $key, $raw_output = false) {
    // 如果密钥长度超过块大小，先对其进行哈希
    $block_size = 64; // HMAC标准块大小
    if (strlen($key) > $block_size) {
        $key = my_hash($key, $algo, true);
    }
    
    // 填充密钥到块大小
    $key = str_pad($key, $block_size, chr(0x00));
    
    // 创建内外填充值
    $opad = str_repeat(chr(0x5c), $block_size);
    $ipad = str_repeat(chr(0x36), $block_size);
    
    // 计算HMAC
    $hmac = my_hash(
        ($key ^ $opad) . my_hash(($key ^ $ipad) . $data, $algo, true),
        $algo,
        $raw_output
    );
    
    return $raw_output ? $hmac : bin2hex($hmac);
}
