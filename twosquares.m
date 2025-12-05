function out=twosquares(text,key1,key2,direction)
% 2 SQUARES Cipher encoder/decoder
% The Two-squares cipher, also called double Playfair, is a manual symmetric
% encryption technique. It was developed to ease the cumbersome nature
% of the large encryption/decryption matrix used in the four-square cipher
% while still being slightly stronger than the single-square Playfair
% cipher. The technique encrypts pairs of letters (digraphs), and thus
% falls into a category of ciphers known as polygraphic substitution
% ciphers.
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax: 	out=twosquares(text,key1,key2,direction)
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
% out=twosquares('Hide the gold into the tree stump','leprachaun','ghosts and goblins',1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%     encrypted: 'AFEDPAGEUHIDLRUEDFRTOFURAQOX'
%
% out=twosquares('AFEDPAGEUHIDLRUEDFRTOFURAQOX','leprachaun','ghosts and goblins',-1)
%
% out =
%
%   struct with fields:
%
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%     encrypted: 'AFEDPAGEUHIDLRUEDFRTOFURAQOX'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, trifid
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
ctext=double(upper(text));
ctext(ctext<65 | ctext>90)=[];

% --- Filter and normalize keys (for output) ---
ckey1_raw=double(upper(key1));
ckey1_raw(ckey1_raw>90 | ckey1_raw<65)=[];

ckey2_raw=double(upper(key2));
ckey2_raw(ckey2_raw>90 | ckey2_raw<65)=[];

% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey1_raw(ckey1_raw==74)=73;
ckey2_raw(ckey2_raw==74)=73;

% Store processed text before any padding/transform
switch direction
    case 1
        plainFiltered = ctext;
    case -1
        encryptedFiltered = ctext;
end

% Output keys should reflect the provided keywords after filtering,
% not the deduplicated versions used to build squares.
out.key1=char(ckey1_raw);
out.key2=char(ckey2_raw);

% --- Deduplicate keys only for square construction ---
ckey1=unique(ckey1_raw,'stable');
ckey2=unique(ckey2_raw,'stable');

% PS = ASCII codes for [ABCDEFGHIKLMNOPQRSTUVWXYZ]
A=[65:1:73 75:1:90];

% Polybius squares generation from Key1 and Key2
% In decryption, squares are swapped to reuse the same transform rule.
switch direction
    case 1
        PS1=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])';
        PS2=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])';
    case -1
        PS1=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])';
        PS2=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])';
end
clear A ckey1 ckey2

% Break the message into digrams (groups of 2 letters)
L=numel(ctext);

switch direction
    case 1
        if mod(L,2)==1
            ctext(end+1)=88; % add an 'X'
            L=L+1;
        end
    case -1
        assert(mod(L,2)==0,'Ciphertext length must be even after filtering.')
end

L=L/2;
ctext=reshape(ctext,2,L)';

for I=1:L
    [R1,C1]=find(PS1==ctext(I,1));
    [R2,C2]=find(PS2==ctext(I,2));

    if R1~=R2
        ctext(I,:)=[PS2(R1,C2) PS1(R2,C1)];
    else
        tmp=ctext(I,1);
        ctext(I,1)=ctext(I,2);
        ctext(I,2)=tmp;
    end
end
clear I R1 C1 R2 C2 PS1 PS2 tmp L

switch direction
    case 1 % encrypt
        out.plain=char(plainFiltered);
        out.encrypted=char(reshape(ctext',1,[]));
    case -1 % decrypt
        out.encrypted=char(encryptedFiltered);
        out.plain=char(reshape(ctext',1,[]));

        % Remove padding X if likely added
        if numel(out.plain) >= 2
            if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
                out.plain(end)=[];
            end
        end
end

clear ctext ckey1_raw ckey2_raw plainFiltered encryptedFiltered
end
