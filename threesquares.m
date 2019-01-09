function out=threesquares(text,key1,key2,key3,direction)
% 3 SQUARES Cipher encoder/decoder
% Three-squares encryption uses three 5x5 Polybius grids to combine to
% extract letters with a bit randomness. 
% The plain message is splitted into bigrams (pairs of two letters L1 and
% L2). Each bigrams will be transformed into trigram. L1 is searched into
% square 1 and L2 into square 2. The intersection in grid 3 of the line of
% L1 in grid 1 with the column of L2 in the grid 2 will be the central
% letter of the trigram; a letter taken randomly in the same column as the
% letter in the grid 1 will be the first letter of the trigram, a letter
% taken randomly in the same line as the letter of the grid 2 will be the
% third letter of the trigram. As a consequence, the same messagge and the
% same keys will differently encoded if the cipher is applied more times.
% 
% Syntax: 	out=threesquares(text,key1,key2,key3,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key1 - It is the keyword used to generate Polybius Square A. 
%           key2 - It is the keyword used to generate Polybius Square B. 
%           key3 - It is the keyword used to generate Polybius Square C. 
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
% out=threesquares('Hide the gold in the tree stump','leprachaun','goblin secret','rainbow',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLINSECRET'
%          key3: 'RAINBOW'
%     encrypted: 'WEILHRTTTHRBWSILLIYODWCNKTROIRSMTXWUQIY'
%
% if you re-run the function:
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLINSECRET'
%          key3: 'RAINBOW'
%     encrypted: 'OEOMHNTTTHRGESIMLOYOTFCSTTCEIEIMFQWQUIY'
%
% both are decrypted in the same message
%
% out=threesquares('WEILHRTTTHRBWSILLIYODWCNKTROIRSMTXWUQIY','leprachaun','goblin secret','rainbow',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'WEILHRTTTHRBWSILLIYODWCNKTROIRSMTXWUQIY'
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLINSECRET'
%          key3: 'RAINBOW'
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%
% out=threesquares('OEOMHNTTTHRGESIMLOYOTFCSTTCEIEIMFQWQUIY','leprachaun','goblin secret','rainbow',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'OEOMHNTTTHRGESIMLOYOTFCSTTCEIEIMFQWQUIY'
%          key1: 'LEPRACHAUN'
%          key2: 'GOBLINSECRET'
%          key3: 'RAINBOW'
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it'

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key1',@(x) ischar(x));
addRequired(p,'key2',@(x) ischar(x));
addRequired(p,'key3',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,key3,direction);

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
ckey1=double(upper(key1)); ckey1(ckey1>90 | ckey1<65)=[]; 
ckey2=double(upper(key2)); ckey2(ckey2>90 | ckey2<65)=[]; 
ckey3=double(upper(key3)); ckey3(ckey3>90 | ckey3<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey1(ckey1==74)=73; 
ckey2(ckey2==74)=73; 
ckey3(ckey3==74)=73; 

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end
out.key1=char(ckey1);
out.key2=char(ckey2);
out.key3=char(ckey3);

%PS=ASCII CODES FOR [ABCDEFGHIKLMNOPQRSTUVWXYZ]
A=[65:1:73 75:1:90]; 
% Polybius squares generation from Key1 and Key2
% Using the key "PLAYFAIR EXAMPLE"
% Chars of the key must be choosen only once
% PLAYFIREXM
ckey1=unique(ckey1,'stable');
ckey2=unique(ckey2,'stable');
ckey3=unique(ckey3,'stable');
% then all the others into alphabetic order

%    1   2   3   4   5
% 1  P   L   A   Y   F
% 2  I   R   E   X   M
% 3  B   C   D   G   H
% 4  K   N   O   Q   S
% 5  T   U   V   W   Z
PSA=reshape([ckey1 A(~ismember(A,ckey1))],[5,5])';
PSB=reshape([ckey2 A(~ismember(A,ckey2))],[5,5])';
PSC=reshape([ckey3 A(~ismember(A,ckey3))],[5,5])';
clear A ckey*

switch direction
    case 1 %encrypt
        % To encrypt a message, one would break the message into
        % digrams(groups of 2 letters) such that, for example, "HelloWorld" becomes
        % "HE LL OW OR LD".
        L=length(ctext);
        if mod(L,2)==1 %if plaintext has and odd length
            ctext(end+1)=88; %add an 'X'
        end
        L=ceil(L/2);
        ctext=reshape(ctext,2,L)';
        ctext2=zeros(L,3);
        for I=1:L
            [R1,C1]=find(PSA==ctext(I,1)); %find row and column of the 1st digram letter into the Polybius Square A
            [R2,C2]=find(PSB==ctext(I,2)); %find row and column of the 2nd digram letter into the Polybius Square B
            ctext2(I,:)=[PSA(randi([1 5]),C1) PSC(R1,C2) PSB(R2,randi([1 5]))];
        end
        clear PS* R* C* I ctext
        out.encrypted=char(reshape(ctext2',1,L*3));
        clear ctext2
    case -1 %decrypt
        % To decrypt a message, one would break the message into trigrams (groups of 3 letters)
        L=length(ctext)/3;
        ctext=reshape(ctext,3,L)';
        ctext2=zeros(L,2);
        for I=1:L
            [~,C1]=find(PSA==ctext(I,1)); %find row and column of the 1st trigram letter into the Polybius Square A
            [R2,~]=find(PSB==ctext(I,3)); %find row and column of the 3rd trigram letter into the Polybius Square B
            [R3,C3]=find(PSC==ctext(I,2)); %find row and column of the 2nd trigram letter into the Polybius Square C
            ctext2(I,:)=[PSA(R3,C1) PSB(R2,C3)];
        end
        clear PS* R* C* I ctext
        out.plain=char(reshape(ctext2',1,L*2));
        clear ctext2
        if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
            %if last letter is 'X' and the second last is not a vowel then
            %erase the 'X': it was added to pad text.
            out.plain(end)=[];
        end
end