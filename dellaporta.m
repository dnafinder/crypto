function out=dellaporta(text,key,direction)
% DELLAPORTA Cipher encoder/decoder
% The Della Porta Cipher is a polyalphabetic substitution cipher invented by
% Giovanni Battista della Porta. Where the Vigenère cipher is a
% polyalphabetic cipher with 26 alphabets, the Porta is basically the same
% except it only uses 13 alphabets. The 13 cipher alphabets it uses are
% reciprocal, so enciphering is the same as deciphering.
%
% Note:
% This implementation works on the modern English A–Z alphabet.
% Non-alphabetic characters are removed during preprocessing.
%
% Syntax: 	out=dellaporta(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the keyword
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
% out=dellaporta('Hide the gold into the tree stump','leprachaun',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%           key: 'LEPRACHAUN'
%     encrypted: 'ZXXZGVUTERVXGLBFXRJLWTLLHNM'
%
% out=dellaporta('ZXXZGVUTERVXGLBFXRJLWTLLHNM','leprachaun',-1)
%
% out =
%
%   struct with fields:
%
%     encrypted: 'ZXXZGVUTERVXGLBFXRJLWTLLHNM'
%           key: 'LEPRACHAUN'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also autokey, beaufort, gronsfeld, trithemius, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% The Della Porta Cipher uses the following tableau:
%
%   Keys| a b c d e f g h i j k l m n o p q r s t u v w x y z
%   ---------------------------------------------------------
%   A,B | n o p q r s t u v w x y z a b c d e f g h i j k l m
%   C,D | o p q r s t u v w x y z n m a b c d e f g h i j k l
%   E,F | p q r s t u v w x y z n o l m a b c d e f g h i j k
%   G,H | q r s t u v w x y z n o p k l m a b c d e f g h i j
%   I,J | r s t u v w x y z n o p q j k l m a b c d e f g h i
%   K,L | s t u v w x y z n o p q r i j k l m a b c d e f g h
%   M,N | t u v w x y z n o p q r s h i j k l m a b c d e f g
%   O,P | u v w x y z n o p q r s t g h i j k l m a b c d e f
%   Q,R | v w x y z n o p q r s t u f g h i j k l m a b c d e
%   S,T | w x y z n o p q r s t u v e f g h i j k l m a b c d
%   U,V | x y z n o p q r s t u v w d e f g h i j k l m a b c
%   W,X | y z n o p q r s t u v w x c d e f g h i j k l m a b
%   Y,Z | z n o p q r s t u v w x y b c d e f g h i j k l m a

% Build the 13 reciprocal alphabets as ASCII codes.
tr1 = zeros(13,13);
tr2 = zeros(13,13);
tr1(1,:) = 14:26;
tr2(1,:) = 1:13;
for I = 2:13
    tr1(I,:) = circshift(tr1(I-1,:),-1);
    tr2(I,:) = circshift(tr2(I-1,:), 1);
end
tr = [tr1 tr2] + 64;
clear I tr1 tr2

% Preprocessing: uppercase and keep only A–Z.
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];
ckey  = double(upper(key));
ckey(ckey  < 65 | ckey  > 90) = [];

assert(~isempty(ckey), 'Key must contain at least one alphabetic character.');

switch direction
    case 1 % encrypt
        out.plain = char(ctext);
    case -1 % decrypt
        out.encrypted = char(ctext);
end
out.key = char(ckey);

% If text becomes empty after preprocessing, return consistent empty output.
if isempty(ctext)
    switch direction
        case 1
            out.encrypted = '';
        case -1
            out.plain = '';
    end
    return
end

% Repeat the key to cover all the text.
LT = numel(ctext);
LK = numel(ckey);
RL = ceil(LT / LK);
ckey2 = repmat(ckey,1,RL);
ckey2 = ckey2(1:LT);
clear LK RL

% Convert letters to positions: A->1 ... Z->26.
ptext = ctext - 64;
pkey  = ckey2 - 64;

% Group index for Della Porta rows:
% A,B -> 1; C,D -> 2; ... ; Y,Z -> 13.
g = ceil(pkey / 2);

switch direction
    case 1 % encrypt
        ind = sub2ind(size(tr), g, ptext);
        tmp = tr(ind);
        out.encrypted = char(tmp);
        clear ind tmp
    case -1 % decrypt
        cipher = ctext; % already filtered A–Z
        pplain = zeros(1,LT);
        for I = 1:LT
            col = find(tr(g(I),:) == cipher(I), 1, 'first');
            assert(~isempty(col), ...
                'Invalid ciphertext character at position %d for this key.', I);
            pplain(I) = col;
        end
        out.plain = char(pplain + 64);
        clear cipher pplain col I
end

clear ctext ckey ckey2 ptext pkey g LT tr
end
