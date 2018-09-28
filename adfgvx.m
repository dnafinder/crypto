function out=adfgvx(text,key,direction,varargin)
% ADFGVX Cipher encoder/decoder
% In cryptography, the ADFGVX cipher was a field cipher used by the German
% Army on the Western Front during World War I. ADFGVX was in fact an
% extension of an earlier cipher called ADFGX. Invented by Lieutenant Fritz
% Nebel (1891–1977) and introduced in March 1918, the cipher was a
% fractionating transposition cipher which combined a modified Polybius
% square with a single columnar transposition. The cipher is named after
% the six possible letters used in the ciphertext: A, D, F, G, V and X. The
% letters were chosen deliberately because they are very different from one
% another in the Morse code. That reduced the possibility of operator
% error. Nebel designed the cipher to provide an army on the move with
% encryption that was more convenient than trench codes but was still
% secure. In fact, the Germans believed the ADFGVX cipher was unbreakable.
% In June 1918, an additional letter, V, was added to the cipher. That
% expanded the grid to 6 × 6, allowing 36 characters to be used. That
% allowed the full alphabet (instead of combining I and J) and the digits
% from 0 to 9. That mainly had the effect of considerably shortening
% messages containing many numbers.
%
% Syntax: 	out=adfgx(text,key,direction,matrix)
%
%     Input:
%           text - It is a characters array to encode or decode
%           key - It is the keyword
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%           matrix - a scrambled 6x6 Polybius matrix. If it is empty and
%           direction is 1, the software will generate it.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.matrix = the used matrix
%           out.encrypted = the coded text
%
% Examples:
%
% out=adfgvx('Attack at 1200am','privacy',1,['NA1C3H';'8TB2OM';'E5WRPD';'4F6G7I';'9J0KLQ';'SUVXYZ'])
% 
% out = 
% 
%   struct with fields:
% 
%        matrix: [6×6 char]
%           key: 'privacy'
%         plain: 'Attack at 1200am'
%     encrypted: 'DGDDDAGDDGAFADDFDADVDVFAADVX'
%
% out=adfgvx('DGDDDAGDDGAFADDFDADVDVFAADVX','privacy',-1,['NA1C3H';'8TB2OM';'E5WRPD';'4F6G7I';'9J0KLQ';'SUVXYZ'])
% 
% out = 
% 
%   struct with fields:
% 
%        matrix: [6×6 char]
%           key: 'privacy'
%     encrypted: 'DGDDDAGDDGAFADDFDADVDVFAADVX'
%         plain: 'ATTACKAT1200AM'
%
% See also adfvgx, foursquare, nihilist, playfair, polybius, twosquare
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'matrix',[],@(x) isempty(x) | (isequal(size(x),[6,6]) && ischar(x)));
parse(p,text,key,direction,varargin{:});
matrix=p.Results.matrix; clear p

A=[48:1:57 65:1:90];
if isempty(matrix) %if there is not a coding matrix
    %if you must decrypt... exit
    assert(direction==1,'This algorithm cannot decode without a matrix')
    %otherwise scramble the A vector and reshape into a 6x6 matrix
    cmatrix=reshape(A(randperm(36)),[6,6]);
    out.matrix=char(cmatrix);
else
    cmatrix=double(upper(matrix));
    %check if matrix use all standard English alphabet and numbers
    assert(all(ismember(cmatrix(:),A)),'Matrix must use standard English alphabet and numbers from 0 to 9')
    out.matrix=upper(matrix);
end
clear A
out.key=key;

%ASCII CODES FOR [ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]; remove the others
ctext=double(upper(text)); ctext(ctext<48 | ctext>90 | (ctext>57 & ctext<65))=[];
ckey=double(upper(key)); ckey(ckey<48 | ckey>90 | (ckey>57 & ckey<65))=[];
%Sort letters in the key
[~,Idx]=sort(ckey);

% as in the example, the secret mixed alphabet is first filled into a 6×6 Polybius square:
%    	A 	D 	F 	G 	V 	X
% A 	N 	A 	1 	C 	3 	H
% D 	8 	T 	B 	2 	O 	M
% F 	E 	5 	W 	R 	P 	D
% G 	4 	F 	6 	G 	7 	I
% V 	9 	J 	0 	K 	L 	Q
% X 	S 	U 	V 	X 	Y 	Z
switch direction
    case 1 %encrypt
        out.plain=text;
        %By using the square, the message is converted to fractionated form:
        %A 	T 	T 	A 	C 	K 	A 	T 	1 	2 	0 	0 	A 	M
        %AD	DD 	DD 	AD 	AG 	VG 	AD 	DD 	AF 	DG 	VF 	VF 	AD 	DX
        P={'A' 'D' 'F' 'G' 'V' 'X'};
        % Find the index of each characters into Polybius square
        [~,locb]=ismember(ctext,cmatrix);
        % transform index into subscripts
        [I,J]=ind2sub([6,6],locb);
        % transform into ADFGVX coding
        tmp=(char(strcat(P(I'),P(J'))))';
        %tmp = ADDAAVADADVVAD
        %      DDDDGGDDFGFFDX
        clear P
        out1=tmp(:)';
        %out1=ADDDDDADAGVGADDDAFDGVFVFADDX
        clear locb I J tmp
        %Next, the fractionated message is subject to a columnar
        %transposition. The message is written in rows under a
        %transposition key (here "PRIVACY"):
        %P R I V A C Y
        %_____________
        %A D D D D D A
        %D A G V G A D
        %D D A F D G V
        %F V F A D D X
        %To do this, the length of the message must be a multiple of key
        %length
        L=length(out1); %length of the message
        C=length(ckey); %length of the key (columns)
        R=ceil(L/C); %how many rows we need?
        if L~=C
            tmp=strcat(out1,repmat('Z',1,C*R-L)); %padding
        end
        tmp=reshape(tmp,C,R)';
        %Next, the letters are sorted alphabetically in the transposition
        %key (changing PRIVACY to ACIPRVY) by rearranging the columns beneath
        %the letters along with the letters themselves:
        %A C I P R V Y
        %_____________
        %D D D A D D A
        %G A G D A V D
        %D G A D D F V
        %D D F F V A X
        tmp=tmp(:,Idx);
        clear Idx
        %Then, it is read off in columns, in keyword order, which yields
        %the ciphertext.
        tmp=tmp(:)';
        %tmp=DGDDDAGDDGAFADDFDADVDVFAADVX
        tmp(tmp=='Z')=[]; %eventually remove padding 'Z'
        out.encrypted=tmp;
        clear tmp
    case -1 %decrypt
        out.encrypted=text;
        %ASCII code for ADFGVX
        P=double('ADFGVX');
        %check that all letters into encoded text are ADFGX
        assert(all(ismember(ctext,P)))
        L=length(ctext); %length of the message
        C=length(ckey); %length of the key (columns)
        R=ceil(L/C); %how many rows we need?
        N=C*R; %number of the elements of the matrix
        tmp=zeros(R,C); %vector preallocation
        if L<N %we need padding
            padding=C-N+L+1; %starting column to pad
            tmp(R,padding:C)=90; %pad
            %tmp = 0 0 0 0 0 0 0
            %      0 0 0 0 0 0 0
            %      0 0 0 0 0 0 0
            %      0 0 0 0 0 0 0
            for I=1:C %fill the columns into the Idx order
                if Idx(I)<padding %if the column number to fill is not a padded column
                    tmp(:,Idx(I))=ctext(1:R); %fill it
                    ctext(1:R)=[]; %erase the letters that were added
                else
                    tmp(1:R-1,Idx(I))=ctext(1:R-1); %add R-1 letters
                    ctext(1:R-1)=[]; %erase the letters that were added
                end
            end
            clear padding
        else %we don't need padding
            tmp2=reshape(ctext,R,C); %reshape array into a matrix
            %tmp2 = 68    68    68    65    68    68    65
            %       71    65    71    68    65    86    68
            %       68    71    65    68    68    70    86
            %       68    68    70    70    86    65    88
            tmp(:,Idx)=tmp2(:,1:C); %back revert the order of the columns
            %tmp = 65    68    68    68    68    68    65
            %      68    65    71    86    71    65    68
            %      68    68    65    70    68    71    86
            %      70    86    70    65    68    68    88
            clear tmp2
        end
        %transform the matrix into a vector
        tmp=tmp';
        out1=tmp(:)';
        %erase the eventually present pads
        out1(out1==90)=[];
        %out1=ADDDDDADAGVGADDDAFDGVFVFADDX
        clear tmp C ctext ckey I Idx L N R
        R=out1(1:2:end); %rows are odds positions of out1
        C=out1(2:2:end); %cols are even positions of out1
        for I=1:6 %convert A=1 D=2 F=3 G=4 V=5 X=6
            R(R==P(I))=I;
            C(C==P(I))=I;
        end
        ind=sub2ind([6,6],R,C); %convert subs to index
        out.plain=matrix(ind); %find letters into the matrix
        clear ind R C I
end