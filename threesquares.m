function out=threesquares(text,key1,key2,key3,direction)
% 3 SQUARES Cipher encoder/decoder
% Three-squares encryption uses three 5x5 Polybius grids to combine to
% extract letters with a bit randomness.
% The plain message is split into bigrams (pairs of two letters L1 and L2).
% Each bigram will be transformed into a trigram. L1 is searched into
% square 1 and L2 into square 2. The intersection in grid 3 of the row of
% L1 in grid 1 with the column of L2 in the grid 2 will be the central
% letter of the trigram; a letter taken randomly in the same column as the
% letter in the grid 1 will be the first letter of the trigram, a letter
% taken randomly in the same row as the letter of the grid 2 will be the
% third letter of the trigram. As a consequence, the same message and the
% same keys will be differently encoded if the cipher is applied more times.
%
% English, 26 letters, alphabet is used.
% Only letters A-Z are processed; other characters are ignored in the
% transformation. J is merged into I.
%
% Syntax: 	out=threesquares(text,key1,key2,key3,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key1 - It is the keyword used to generate Polybius Square A
%                  (character array or string scalar)
%           key2 - It is the keyword used to generate Polybius Square B
%                  (character array or string scalar)
%           key3 - It is the keyword used to generate Polybius Square C
%                  (character array or string scalar)
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key1 = the used key1
%           out.key2 = the used key2
%           out.key3 = the used key3
%           out.encrypted = the coded text
%
% Examples:
%
% out=threesquares('Hide the gold into the tree stump','leprachaun','ghosts','goblins',1)
%
% if you re-run the function, the encrypted text changes,
% but both are decrypted in the same message.
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares,
% nihilist, playfair, polybius, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key3',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,key3,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key1); key1 = char(key1); end
if isstring(key2); key2 = char(key2); end
if isstring(key3); key3 = char(key3); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% --- Filter and normalize text ---
ctext=double(upper(text));
ctext(ctext<65 | ctext>90)=[];

% --- Filter and normalize keys (for output) ---
ckey1_raw=double(upper(key1));
ckey1_raw(ckey1_raw>90 | ckey1_raw<65)=[];

ckey2_raw=double(upper(key2));
ckey2_raw(ckey2_raw>90 | ckey2_raw<65)=[];

ckey3_raw=double(upper(key3));
ckey3_raw(ckey3_raw>90 | ckey3_raw<65)=[];

% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey1_raw(ckey1_raw==74)=73;
ckey2_raw(ckey2_raw==74)=73;
ckey3_raw(ckey3_raw==74)=73;

% Output keys should reflect the provided keywords after filtering,
% not the deduplicated versions used to build squares.
out.key1=char(ckey1_raw);
out.key2=char(ckey2_raw);
out.key3=char(ckey3_raw);

% --- Deduplicate keys only for square construction ---
ckey1=unique(ckey1_raw,'stable');
ckey2=unique(ckey2_raw,'stable');
ckey3=unique(ckey3_raw,'stable');

% PS = ASCII codes for [ABCDEFGHIKLMNOPQRSTUVWXYZ]
A=[65:1:73 75:1:90];

% Polybius squares generation from Key1, Key2, Key3
PSA=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])';
PSB=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])';
PSC=reshape([ckey3 A(~ismember(A,ckey3))],[5,5])';
clear A ckey1 ckey2 ckey3

switch direction
    case 1 % encrypt
        plainFiltered = ctext;

        L=numel(ctext);
        if mod(L,2)==1
            ctext(end+1)=88; % add an 'X'
            L=L+1;
        end

        L=L/2;
        ctext=reshape(ctext,2,L)';

        ctext2=zeros(L,3);
        for I=1:L
            [R1,C1]=find(PSA==ctext(I,1));
            [R2,C2]=find(PSB==ctext(I,2));
            ctext2(I,:)=[PSA(randi(5),C1) PSC(R1,C2) PSB(R2,randi(5))];
        end

        out.plain=char(plainFiltered);
        out.encrypted=char(reshape(ctext2',1,[]));

        clear plainFiltered ctext ctext2 I L R1 C1 R2 C2

    case -1 % decrypt
        encryptedFiltered = ctext;

        assert(mod(numel(ctext),3)==0, ...
            'Ciphertext length must be a multiple of 3 after filtering.')

        L=numel(ctext)/3;
        ctext=reshape(ctext,3,L)';

        ctext2=zeros(L,2);
        for I=1:L
            [~,C1]=find(PSA==ctext(I,1));
            [R2,~]=find(PSB==ctext(I,3));
            [R3,C3]=find(PSC==ctext(I,2));
            ctext2(I,:)=[PSA(R3,C1) PSB(R2,C3)];
        end

        out.encrypted=char(encryptedFiltered);
        out.plain=char(reshape(ctext2',1,[]));

        if numel(out.plain) >= 2
            if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
                out.plain(end)=[];
            end
        end

        clear encryptedFiltered ctext ctext2 I L C1 R2 R3 C3
end

clear PSA PSB PSC ckey1_raw ckey2_raw ckey3_raw
end
