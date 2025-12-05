function out=foursquares(text,key1,key2,direction)
% 4 SQUARES Cipher encoder/decoder
% The four-squares cipher is a manual symmetric encryption technique. It
% was invented by the French cryptographer Felix Delastelle. The technique
% encrypts pairs of letters (digraphs), and thus falls into a category of
% ciphers known as polygraphic substitution ciphers.
%
% The four-squares cipher uses four 5x5 Polybius Squares.
% In general, the upper-left and lower-right matrices are the "plaintext
% squares" and each contain a standard alphabet. The upper-right and
% lower-left squares are the "ciphertext squares" and contain a mixed
% alphabetic sequence generated from two separate keys.
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax: 	out=foursquares(text,key1,key2,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key1 - It is the keyword used to generate Polybius Square A
%                  (character array or string scalar)
%           key2 - It is the keyword used to generate Polybius Square B
%                  (character array or string scalar)
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key1 = the used key1
%           out.key2 = the used key2
%           out.encrypted = the coded text
%
% Examples:
%
% out=foursquares('Hide the gold into the tree stump','leprachaun','ghosts and goblins',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%     encrypted: 'NDASQBELDFRBIQIRBOORATSQOKGZ'
%
% out=foursquares('NDASQBELDFRBIQIRBOORATSQOKGZ','leprachaun','ghosts and goblins',-1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%     encrypted: 'NDASQBELDFRBIQIRBOORATSQOKGZ'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, nihilist,
% playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key1); key1 = char(key1); end
if isstring(key2); key2 = char(key2); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% --- Filter and normalize text ---
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73; % J -> I

% --- Filter and normalize keys for output ---
ckey1_raw = double(upper(key1));
ckey1_raw(ckey1_raw>90 | ckey1_raw<65) = [];
ckey1_raw(ckey1_raw==74) = 73;

ckey2_raw = double(upper(key2));
ckey2_raw(ckey2_raw>90 | ckey2_raw<65) = [];
ckey2_raw(ckey2_raw==74) = 73;

% Store processed text before padding/transform
switch direction
    case 1
        plainFiltered = ctext;
    case -1
        encryptedFiltered = ctext;
end

% Output keys should reflect provided keywords after filtering,
% not the deduplicated versions used to build squares.
out.key1 = char(ckey1_raw);
out.key2 = char(ckey2_raw);

% --- Deduplicate keys only for square construction ---
ckey1 = unique(ckey1_raw,'stable');
ckey2 = unique(ckey2_raw,'stable');

% PS = ASCII codes for [ABCDEFGHIKLMNOPQRSTUVWXYZ]
A = [65:1:73 75:1:90];
PS  = reshape(A,5,5)'; % standard plaintext square
PSA = reshape([ckey1 A(~ismember(A,ckey1))],[5,5])';
PSB = reshape([ckey2 A(~ismember(A,ckey2))],[5,5])';
clear A ckey1 ckey2

% --- Digram handling ---
L = numel(ctext);

switch direction
    case 1
        if mod(L,2)==1
            ctext(end+1) = 88; % add an 'X'
            L = L + 1;
        end
    case -1
        assert(mod(L,2)==0,'Ciphertext length must be even after filtering.')
end

L = L/2;
ctext = reshape(ctext,2,L)';

for I = 1:L
    switch direction
        case 1 % encrypt
            [R1,C1] = find(PS==ctext(I,1));
            [R2,C2] = find(PS==ctext(I,2));
            ctext(I,:) = [PSA(R1,C2) PSB(R2,C1)];
        case -1 % decrypt
            [R1,C1] = find(PSA==ctext(I,1));
            [R2,C2] = find(PSB==ctext(I,2));
            ctext(I,:) = [PS(R1,C2) PS(R2,C1)];
    end
end
clear R1 R2 C1 C2 I L PS PSA PSB

switch direction
    case 1 % encrypt
        out.plain = char(plainFiltered);
        out.encrypted = char(reshape(ctext',1,[]));
        clear plainFiltered
    case -1 % decrypt
        out.encrypted = char(encryptedFiltered);
        out.plain = char(reshape(ctext',1,[]));
        clear encryptedFiltered

        if numel(out.plain) >= 2
            if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
                out.plain(end) = [];
            end
        end
end

clear ctext ckey1_raw ckey2_raw
end
