function out=checkerboard1(text,pskey,key1,key2,direction)
% CHECKERBOARD1 Cipher encoder/decoder
% This cipher uses a 5x5 Polybius square with I/J combined. The usual
% numeric coordinates are replaced by two 5-letter keys:
%   - key1 for row coordinates
%   - key2 for column coordinates
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax: 	out=checkerboard1(text,pskey,key1,key2,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           pskey - It is the keyword to generate the Polybius square
%                   (character array or string scalar)
%           key1 - It is a 5-letter key for row coordinates
%                   (character array or string scalar)
%           key2 - It is a 5-letter key for column coordinates
%                   (character array or string scalar)
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
% out=checkerboard1('Hide the gold into the tree stump','leprachaun','ghost','ghoul',1)
%
% out=checkerboard1('HHOUOGGHSLHHGHOOSHGGOGOUHUSLSHSLHHGHSLGUGHGHSUSLHOSGGO',...
%                   'leprachaun','ghost','ghoul',-1)
%
% See also adfgx, adfgvx, bifid, checkerboard2, foursquares, nihilist,
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

% --- Filter and normalize main text (A-Z only, J->I) ---
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

% --- Filter and normalize Polybius-square key (raw for output) ---
ckey_raw = double(upper(pskey));
ckey_raw(ckey_raw>90 | ckey_raw<65) = [];
ckey_raw(ckey_raw==74) = 73;

% --- Filter and normalize coordinate keys ---
k1 = double(upper(key1));
k1(k1>90 | k1<65) = [];
k1(k1==74) = 73;

k2 = double(upper(key2));
k2(k2>90 | k2<65) = [];
k2(k2==74) = 73;

assert(numel(k1)==5 && numel(k2)==5, 'Key1 and Key2 must be 5 letters long')
assert(numel(unique(k1))==5 && numel(unique(k2))==5, ...
    'Key1 and Key2 must contain 5 unique letters')

key1u = char(k1);
key2u = char(k2);

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
out.key1  = key1u;
out.key2  = key2u;

% --- Build Polybius square from pskey (deduplicated internally) ---
ckey = unique(ckey_raw,'stable');
A = [65:1:73 75:1:90]; % [ABCDEFGHIKLMNOPQRSTUVWXYZ]
PS = reshape([ckey A(~ismember(A,ckey))],[5,5])';
clear A ckey

switch direction
    case 1 % encrypt
        % Find characters positions in Polybius square
        [~,locb] = ismember(ctext,PS);
        assert(all(locb>0),'Plaintext contains characters not encodable with the generated Polybius square.')

        [I,J] = ind2sub([5,5],locb);

        out.plain = char(plainFiltered);
        out.encrypted = reshape([key1u(I); key2u(J)],1,[]);
        clear plainFiltered I J locb

    case -1 % decrypt
        assert(mod(numel(ctext),2)==0, ...
            'Ciphertext length must be even after filtering.')

        cmat = char(reshape(ctext',2,[]));

        [~,I] = ismember(cmat(1,:),key1u);
        [~,J] = ismember(cmat(2,:),key2u);

        assert(all(I>0) && all(J>0), ...
            'Ciphertext contains coordinates not present in key1/key2.')

        Idx = sub2ind([5,5],I,J);

        out.encrypted = char(encryptedFiltered);
        out.plain = char(PS(Idx));

        clear encryptedFiltered cmat I J Idx
end

clear PS ctext ckey_raw k1 k2 key1u key2u
end
