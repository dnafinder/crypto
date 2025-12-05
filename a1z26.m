function out=a1z26(x)
% A1Z26 Cipher encoder/decoder
% A1Z26 is a very simple direct substitution cipher, where each alphabet
% letter is replaced by its number in the alphabet. English, 26 letters,
% alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation.
%
% Syntax: 	out=a1z26(x)
%
%     Input:
%           x - It can be a character array, a string scalar, or a numeric array.
%               If text is provided it will be encoded; if numbers are provided
%               it will be decoded.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.encrypted = the coded text
%
% Examples:
%
% out=a1z26('Hide the gold into the tree stump')
%
% out =
%
%   struct with fields:
%
%         plain: 'Hide the gold into the tree stump'
%     encrypted: [8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16]
%
% out=a1z26([8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16])
%
% out =
%
%   struct with fields:
%
%     encrypted: [8 9 4 5 20 8 5 7 15 12 4 9 14 20 15 20 8 5 20 18 5 5 19 20 21 13 16]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto
%

if isstring(x) && isscalar(x)
    x = char(x);
end

if isnumeric(x) % decrypt
    assert(isreal(x),'Input numeric array must be real.')
    assert(all(isfinite(x)),'Input numeric array must be finite.')
    assert(all(mod(x,1)==0),'All numbers must be integers.')
    % check that all numbers are between 1 and 26
    assert(all(ismember(x,1:26)),'All numbers must be between 1 and 26')
    
    out.plain=[];
    out.encrypted=x;
    % In ASCII Code uppercase letters are between 65 and 90; so add 64 and
    % convert numbers into letters.
    out.plain=char(x+64);
    
elseif ischar(x) % encrypt
    % Set all letters in uppercase and convert into ASCII Code.
    text=upper(x);
    ctext=double(text);
    % Erase all characters that are not into the range 65 - 90
    ctext(ctext<65 | ctext>90)=[];
    
    out.plain=x;
    % In ASCII Code uppercase letters are between 65 and 90; so subtract 64
    out.encrypted=ctext-64;
    
else
    error('Input must be a character array, a string scalar, or a numeric array.')
end
end
