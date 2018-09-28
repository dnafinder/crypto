function out=threesquares(text,key1,key2,key3,direction)

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

% To encrypt or decrypt a message, one would break the message into
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
    switch direction
        case 1 %encrypt
            [R1,C1]=find(PSA==ctext(I,1)); %find row and column of the 1st digram letter into the Polybius Square A
            [R2,C2]=find(PSB==ctext(I,2)); %find row and column of the 2nd digram letter into the Polybius Square B
            ctext2(I,:)=[PSA(randi([1 5]),C1) PSC(R1,C2) PSB(R2,randi([1 5]))];
        case -1 %decrypt
            [R1,C1]=find(PSA==ctext(I,1)); %find row and column of the 1st digram letter into the Polybius Square A
            [R2,C2]=find(PSB==ctext(I,2)); %find row and column of the 2nd digram letter into the Polybius Square B
            ctext(I,:)=[PS(R1,C2) PS(R2,C1)];
    end
end
clear PS* R* C* I ctext

switch direction
    case 1 %encrypt
        out.encrypted=char(reshape(ctext2',1,L*3));
    case -1 %decrypt
        out.plain=char(reshape(ctext',1,L*2));
        if out.plain(end)=='X' && ~ismember(out.plain(end-1),'AEIOUY')
            %if last letter is 'X' and the second last is not a vowel then
            %erase the 'X': it was added to pad text.
            out.plain(end)=[];
        end
end


