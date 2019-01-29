function out=twosquares(text,key1,key2,direction)
% 2 SQUARES Cipher encoder/decoder
% The Two-squares cipher, also called double Playfair, is a manual symmetric
% encryption technique. It was developed to ease the cumbersome nature
% of the large encryption/decryption matrix used in the four-square cipher
% while still being slightly stronger than the single-square Playfair
% cipher. The technique encrypts pairs of letters (digraphs), and thus
% falls into a category of ciphers known as polygraphic substitution
% ciphers. This adds significant strength to the encryption when compared
% with monographic substitution ciphers, which operate on single
% characters. The use of digraphs makes the two-square technique less
% susceptible to frequency analysis attacks, as the analysis must be done
% on 676 possible digraphs rather than just 26 for monographic
% substitution. The frequency analysis of digraphs is possible, but
% considerably more difficult, and it generally requires a much larger
% ciphertext in order to be useful.
% 
% Syntax: 	out=twosquares(text,key1,key2,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key1 - It is the keyword used to generate Polybius Square A. 
%           key2 - It is the keyword used to generate Polybius Square B. 
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
%     encrypted: 'AFEDPAGEUHIDLRUEDFRTOFURAQOX'
%          key1: 'LEPRACHAUN'
%          key2: 'GHOSTSANDGOBLINS'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, trifid
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it'

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key1',@(x) ischar(x));
addRequired(p,'key2',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,direction);
clear p

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
ckey1=double(upper(key1)); ckey1(ckey1>90 | ckey1<65)=[]; 
ckey2=double(upper(key2)); ckey2(ckey2>90 | ckey2<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey1(ckey1==74)=73; 
ckey2(ckey2==74)=73; 

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end
out.key1=char(ckey1);
out.key2=char(ckey2);

%PS=ASCII CODES FOR [ABCDEFGHIKLMNOPQRSTUVWXYZ]
A=[65:1:73 75:1:90]; 
% Polybius squares generation from Key1 and Key2
% Using the key "PLAYFAIR EXAMPLE"
% Chars of the key must be choosen only once
% PLAYFIREXM
ckey1=unique(ckey1,'stable');
ckey2=unique(ckey2,'stable');
% then all the others into alphabetic order

%    1   2   3   4   5
% 1  P   L   A   Y   F
% 2  I   R   E   X   M
% 3  B   C   D   G   H
% 4  K   N   O   Q   S
% 5  T   U   V   W   Z
switch direction
    case 1
        PS1=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])'; %5x5 Polybius Square 1
        PS2=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])'; %5x5 Polybius Square 2
    case -1
        PS1=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])'; %5x5 Polybius Square 1
        PS2=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])'; %5x5 Polybius Square 2
end
clear A ckey*

% To encrypt or decrypt a message, one would break the message into
% digrams(groups of 2 letters) such that, for example, "HelloWorld" becomes
% "HE LL OW OR LD".  
L=length(ctext);
if mod(L,2)==1 %if plaintext has and odd length
    ctext(end+1)=88; %add an 'X'
end
L=ceil(L/2);
ctext=reshape(ctext,2,L)';

for I=1:L
    [R1,C1]=find(PS1==ctext(I,1)); %find row and column of the 1st digram letter into the Polybius Square 1
    [R2,C2]=find(PS2==ctext(I,2)); %find row and column of the 2nd digram letter into the Polybius Square 2
    if R1~=R2
        ctext(I,:)=[PS2(R1,C2) PS1(R2,C1)];
    else
        tmp=ctext(I,1); ctext(I,1)=ctext(I,2); ctext(I,2)=tmp; 
    end
end
clear I R1 C1 R2 C2 PS1 PS2 tmp

switch direction
    case 1 %encrypt
        out.encrypted=char(reshape(ctext',1,L*2));
    case -1 %decrypt
        out.plain=char(reshape(ctext',1,L*2));
        if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
            %if last letter is 'X' and the second last is not a vowel then
            %erase the 'X': it was added to pad text.
            out.plain(end)=[];
        end
end
clear ctext L
