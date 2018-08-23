function out=keyword(text,key,direction)
% KEYWORD CIPHER encoder/decoder
% A keyword cipher is a form of monoalphabetic substitution. A keyword is
% used as the key, and it determines the letter matchings of the cipher
% alphabet to the plain alphabet. Repeats of letters in the word are
% removed, then the cipher alphabet is generated with the keyword matching
% to A,B,C etc. until the keyword is used up, whereupon the rest of the
% ciphertext letters are used in alphabetical order, excluding those
% already used in the key.      
%
% Plaintext:   A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
% Encrypted:   K R Y P T O S A B C D E F G H I J L M N Q U V W X Z
%
% With KRYPTOS as the keyword, all As become Ks, all Bs become Rs and so on.
% Encrypting the message "knowledge is power" using the keyword "kryptos": 
% 
% Plaintext:   K N O W L E D G E  I S  P O W E R
% Encoded:     D G H V E T P S T  B M  I H V T L
% Only one alphabet is used here, so the cipher is monoalphabetic.
% English, 26 letters, alphabet is used and all non-alphabet symbols are
% not transformed.   
%
% Syntax: 	out=keyword(text,key,direction)
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
% out=keyword('Knowledge is power','kryptos',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'KNOWLEDGEISPOWER'
%           key: 'KRYPTOS'
%     encrypted: 'DGHVETPSTBMIHVTL'
% 
% out=keyword('DGHVETPSTBMIHVTL','kryptos',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'DGHVETPSTBMIHVTL'
%           key: 'KRYPTOS'
%         plain: 'KNOWLEDGEISPOWER'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));

% ASCII codes of standard English 26 letters alphabet
plainal=65:1:90;
% Set all letters in uppercase and convert into ASCII Code.
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
ckey=double(upper(key)); ckey(ckey<65 | ckey>90)=[]; 
% Take not repeated letters into keyword
ckey=unique(ckey,'stable');
% Construct the matrix: into the first row the plain alphabet and into the second row the crypting alphabet
M=[plainal;ckey plainal(~ismember(plainal,ckey))]; clear plainal

switch direction
    case 1
        S=1; E=2;
    case -1
        S=2; E=1;
end
% Preallocate vector
tmp=zeros(1,length(ctext)); 
% unique letters into text (max length 26)
L=unique(ctext);
for I=1:length(L)
    % Find the position into the text
    Idx=ismember(ctext,L(I));
    % Substitute using crypting or plain alphabet
    tmp(Idx)=M(E,M(S,:)==L(I));
end

switch direction
    case 1
        out.plain=char(ctext);
        out.key=char(ckey);
        out.encrypted=char(tmp);
    case -1
        out.encrypted=text;
        out.key=char(ckey);
        out.plain=char(tmp);
end