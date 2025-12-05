function out=rot13(text)
% ROT13 Cipher encoder/decoder
% ROT13 ("rotate by 13 places") is a simple letter substitution cipher that
% replaces a letter with the 13th letter after it, in the alphabet. ROT13
% is a special case of ROT Cipher.
% Because there are 26 letters (2×13) in the basic English alphabet, ROT13
% is its own inverse; that is, to undo ROT13, the same algorithm is
% applied, so the same action can be used for encoding and decoding. The
% algorithm provides virtually no cryptographic security, and is often
% cited as a canonical example of weak encryption.
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation.
%
% Syntax: 	out=rot13(text)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%     Output:
%           out - It is a structure
%           out.input = the input text
%           out.output = output text
%
% Examples:
%
% out=rot13('Hide the gold into the tree stump')
%
% out =
%
%   struct with fields:
%
%      input: 'Hide the gold into the tree stump'
%     output: 'UVQRGURTBYQVAGBGURGERRFGHZC'
%
% out=rot13('UVQRGURTBYQVAGBGURGERRFGHZC')
%
% out =
%
%   struct with fields:
%
%      input: 'UVQRGURTBYQVAGBGURGERRFGHZC'
%     output: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also rot, affine, atbash
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

tmp=rot(text,13,1);
out.input=text;
out.output=tmp.encrypted;
end
