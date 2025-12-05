function out=checkerboard2(text,pskey,key1,key2,direction)
% CHECKERBOARD2 Cipher encoder/decoder
% This cipher uses a 5x5 Polybius square with I/J combined. The usual
% numeric coordinates are replaced by two 2x5 letter keys:
%   - key1 for row coordinates (two 5-letter words)
%   - key2 for column coordinates (two 5-letter words)
% Key A and Key B of each key must not share letters.
%
% The cipher is non-deterministic in encryption: the same plaintext and
% keys can generate different ciphertexts on each run due to random choice
% between Key A and Key B for each coordinate.
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax: 	out=checkerboard2(text,pskey,key1,key2,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           pskey - It is the keyword to generate Polybius square
%                   (character array or string scalar)
%           key1 - It is a 2x5 letters key for row coordinates
%           key2 - It is a 2x5 letters key for column coordinates
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.pskey = the used key to generate Polybius square
%           out.key1 = the used key1 for row coordinates
%           out.key2 = the used key2 for column coordinates
%           out.encrypted = the coded text
%
% Examples:
%
% out=checkerboard2('Hide the gold into the tree stump','leprachaun',['black';'ghost'],['train';'ghoul'],1)
%
% out=checkerboard2('HHOIOTGHCLLHBHOASRGTATOIHUSNCRCLLRGRCNGIBRGHCUSLHOCTBO',...
%                   'leprachaun',['black';'ghost'],['train';'ghoul'],-1)
%
% See also adfgx, adfgvx, bifid, checkerboard1, foursquares, nihilist,
% playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'pskey',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,pskey,key1,key2,direction);
clear p

if isstring(text);  text  = char(text);  end
if isstring(pskey); pskey = char(pskey); end
if isstring(key1);  key1  = char(key1);  end
if isstring(key2);  key2  = char(key2);  end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% --- Validate and normalize coordinate keys ---
key1 = upper(key1);
key2 = upper(key2);

assert(isequal(size(key1),[2 5]) && isequal(size(key2),[2 5]), ...
    'Key1 and Key2 must be 2x5 letters long')

assert(all(key1(:)>='A' & key1(:)<='Z') && all(key2(:)>='A' & key2(:)<='Z'), ...
    'Key1 and Key2 must contain letters A-Z only')

% Convert J into I for consistency with 5x5 square
key1(key1=='J') = 'I';
key2(key2=='J') = 'I';

% Each row should have 5 unique letters
assert(numel(unique(key1(1,:)))==5 && numel(unique(key1(2,:)))==5, ...
    'Each row of key1 must contain 5 unique letters')
assert(numel(unique(key2(1,:)))==5 && numel(unique(key2(2,:)))==5, ...
    'Each row of key2 must contain 5 unique letters')

% Key A and Key B must not share letters
assert(isempty(intersect(key1(1,:),key1(2,:))), ...
    'key1 A and key1 B must not share letters')
assert(isempty(intersect(key2(1,:),key2(2,:))), ...
    'key2 A and key2 B must not share letters')

% --- Filter and normalize main text (A-Z only, J->I) ---
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

% --- Filter and normalize Polybius-square key (raw for output) ---
ckey_raw = double(upper(pskey));
ckey_raw(ckey_raw>90 | ckey_raw<65) = [];
ckey_raw(ckey_raw==74) = 73;

% Store processed text for outputs
switch direction
    case 1
        plainFiltered = ctext;
    case -1
        encryptedFiltered = ctext;
end

% Output keys should reflect provided keywords after filtering,
% not deduplicated versions used to build the square.
out.pskey = char(ckey_raw);
out.key1  = key1;
out.key2  = key2;

% --- Build Polybius square from pskey (deduplicated internally) ---
ckey = unique(ckey_raw,'stable');
A = [65:1:73 75:1:90]; % [ABCDEFGHIKLMNOPQRSTUVWXYZ]
PS = reshape([ckey A(~ismember(A,ckey))],[5,5])';
clear A ckey

switch direction
    case 1 % encrypt
        [~,locb] = ismember(ctext,PS);
        assert(all(locb>0),'Plaintext contains characters not encodable with the generated Polybius square.')

        [I,J] = ind2sub([5,5],locb);
        L = numel(I);

        % Randomly choose between key A and key B for each coordinate
        s1 = randi(2,L,2);

        out.plain = char(plainFiltered);
        out.encrypted = reshape( ...
            [key1(sub2ind([2,5],s1(:,1)',I)); ...
             key2(sub2ind([2,5],s1(:,2)',J))], ...
            1,[]);

        clear plainFiltered I J L s1 locb

    case -1 % decrypt
        assert(mod(numel(ctext),2)==0, ...
            'Ciphertext length must be even after filtering.')

        cmat = char(reshape(ctext',2,[]));

        [~,idx1] = ismember(cmat(1,:),key1);
        [~,idx2] = ismember(cmat(2,:),key2);

        assert(all(idx1>0) && all(idx2>0), ...
            'Ciphertext contains coordinates not present in key1/key2.')

        [~,I] = ind2sub([2,5],idx1);
        [~,J] = ind2sub([2,5],idx2);

        Idx = sub2ind([5,5],I,J);

        out.encrypted = char(encryptedFiltered);
        out.plain = char(PS(Idx));

        clear encryptedFiltered cmat idx1 idx2 I J Idx
end

clear PS ctext ckey_raw
end
