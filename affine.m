function out=affine(text,key,direction)
% AFFINE Cipher encoder/decoder
% The affine cipher is a type of monoalphabetic substitution cipher,
% wherein each letter in an alphabet is mapped to its numeric equivalent,
% encrypted using a simple mathematical function, and converted back to a
% letter. The formula used means that each letter encrypts to one other
% letter, and back again, meaning the cipher is essentially a standard
% substitution cipher with a rule governing which letter goes to which. As
% such, it has the weaknesses of all substitution ciphers. Each letter is
% enciphered with the function (ax + b) mod 26, where b is the magnitude of
% the shift.
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.
%
% Syntax: 	out=affine(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - This is a 1x2 vector containing A and B keys. 
%                 Key A must be coprime with 26 (1 3 5 7 9 11 15 17 19 21 23 25). 
%                 When key A = 1 affine cipher is equal to rot cipher
%                 Key B must be between -25 and 25 (0 excluded)
%           direction - this parameter can assume only two values: 
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.encrypted = the coded text
%
% Examples:
%
% out=affine('Hide the gold into the tree stump',[5 8],1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%           key: [5 8]
%     encrypted: 'RWXCZRCMALXWVZAZRCZPCCUZEQF'
%
% out=affine('RWXCZRCMALXWVZAZRCZPCCUZEQF',[5 8],-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'RWXCZRCMALXWVZAZRCZPCCUZEQF'
%           key: [5 8]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also rot, rot13, atbash
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) validateattributes(x,{'numeric'},{'row','ncols',2,'real','finite','nonnan','nonempty','integer','nonzero'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

assert(ismember(key(1),[1 3 5 7 9 11 15 17 19 21 23 25]),'Key A must be coprime with 26')
assert(key(2)>=-25 & key(2)<=25,'Key B must be between -25 and 25 (0 excluded)')

% Set all letters in uppercase and convert into ASCII Code.
text=upper(text); ctext=double(text); 
% Erase all characters that are not into the range 65 - 90
ctext(ctext<65 | ctext>90)=[];

switch direction
    case 1 % encrypt
        out.plain=text;
        out.key=key;
        % The encryption can also be represented using modular arithmetic by first
        % transforming the letters into numbers, according to the scheme, A → 0, B →
        % 1, ..., Z → 25. The encryption function is:
        % En(x) = (a*x + b) mod 26    
        out.encrypted=char(mod(((ctext-65).*key(1)+key(2)),26)+65);
    case -1 % decrypt
        out.encrypted=text;
        out.key=key;
        % The decryption function is: 
        % Dn(x)= a^−1*(x−b) mod 26
        % where a^−1 is the modular multiplicative inverse of a modulo 26.
        % and it satisfies the equation: 
        % 1=a*a^−1 mod 26
        % The multiplicative inverse of a only exists if a and 26 are coprime. 
        % Hence without the restriction on a, decryption might not be possible.
        [~, C, ~] = gcd(key(1),26);
        ainv=mod(C,26);
        out.plain=char(mod(ainv.*(double(ctext)-65-key(2)),26)+65);
end