function out=bazeries(text,key,direction)
% BAZERIES Cipher encoder/decoder
% A simple substitution with trasposition. The Bazeries Cipher is a
% ciphering system created by Etienne Bazeries combining two grids
% (Polybius), and one key creating super-encryption.  
% One of the squares features the alphabet written vertically in order. For
% the other square, choose a number less than a million, spell it out, and
% use it as the keyword for the other Polybius square, written
% horizontally. Finally, take the plaintext and split it into groups, with
% each group being the length of each digit in the key number. Reverse
% the text in each group. The normal alphabet Polybius square represents
% the plaintext letter, and the keyed horizontal Polybius square represents
% the ciphertext letter to replace it with.  
%
% Syntax: 	out=bazeries(text,key,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is a characters array of the digits used as key.
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
% out=bazeries('Hide the gold into the tree stump','81257',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%           key: '81257'
%     encrypted: 'OMDKMVBDCVGKCKWBRMMUKMDQNXK'
% 
% out=bazeries('OMDKMVBDCVGKCKWBRMMUKMDQNXK','81257',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'OMDKMVBDCVGKCKWBRMMUKMDQNXK'
%           key: '81257'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also polybius
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

nk=str2double(key);
assert(nk<1e6,'Key must be less than 1 million')

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73; ctext=char(ctext);
LT=length(ctext);
% Convert key into a vector
K=double(key)-48;
LK=length(K); %how many columns?

%Polybius square generation from Key
%First a number less than a million is chosen (say 3752). It is spelled out
%and used as the key in a 5x5 ciphertext Polybius square entered in
%left-to-right horizontal rows. 
%A  5x5 plaintext Polybius square is used with the alphabet in normal order
%vertically. In the ciphertext and plaintext squares, I and J (I/J) are
%combined in one cell.  
A=[65:1:73 75:1:90];
% PS1 =
% AFLQV
% BGMRW
% CHNSX
% DIOTY
% EKPUZ
switch direction
    case 1
        out.plain=text;
        PS1=char(reshape(A,5,5));
        % key=Three Thousand Seven Hundred Fifty Two
        ckey=unique(regexprep(upper(num2words(nk)),' ',''),'stable');
        % ckey=THREOUSANDVFIYW
        PS2=reshape([ckey A(~ismember(A,ckey))],[5,5])';
        % PS2 =
        % THREO
        % USAND
        % VFIYW
        % BCGKL
        % MPQXZ
    case -1
        out.encrypted=text;
        PS2=char(reshape(A,5,5));
        % key=Three Thousand Seven Hundred Fifty Two
        ckey=unique(regexprep(upper(num2words(nk)),' ',''),'stable');
        % ckey=THREOUSANDVFIYW
        PS1=reshape([ckey A(~ismember(A,ckey))],[5,5])';
        % PS2 =
        % THREO
        % USAND
        % VFIYW
        % BCGKL
        % MPQXZ
end
out.key=key;
clear ckey A nk

% The plaintext is divided into groups governed by the key numbers, in this
% example:3, 7, 5, and 2. Letters within each group are reversed.
% The result is enciphered using the squares to match.
flag=1; start=1; I=1;
while flag==1
    stop=start+K(I)-1;
    if stop>LT
        stop=LT;
        flag=0;
    end
    ctext(start:stop)=fliplr(ctext(start:stop));
    start=stop+1;
    I=I+1;
    if I>LK
        I=1;
    end
end
clear flag start stop I K LK

for I=1:LT
    [R,C]=find(PS1==ctext(I)); %find row and column of the i-th letter into the Polybius Square 1
    ctext(I)=PS2(R,C); %change the I-th letter with the corresponding letter into Polybius Square 2
end
clear R C PS* I LT

switch direction
    case 1
        out.encrypted=ctext;
    case -1
        out.plain=ctext;
end
clear ctext;