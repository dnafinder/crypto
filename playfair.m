function out=playfair(text,key,direction)
% PLAYFAIR CIPHER encoder/decoder
% The Playfair cipher was the first cipher to encrypt pairs of letters in
% cryptologic history. Wheatstone invented the cipher for secrecy in
% telegraphy, but it carries the name of his friend Lord Playfair, first
% Baron Playfair of St. Andrews, who promoted its use. Playfair is no
% longer used by military forces because of the advent of digital
% encryption devices. This cipher is now regarded as insecure for any
% purpose, because modern computers could easily break it within seconds.   
% Playfair Cipher is based onto Polybius Square.
%
% Syntax: 	out=playfair(text,key,direction)
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
% out=playfair('Hide the gold in the tree stump','playfair example',1)
%
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%           key: 'PLAYFAIREXAMPLE'
%     encrypted: 'BMODZBXDNABEKUDMUIXMMOUVIF'
%
% out=playfair('BMODZBXDNABEKUDMUIXMMOUVIF','playfair example',-1)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'BMODZBXDNABEKUDMUIXMMOUVIF'
%           key: 'PLAYFAIREXAMPLE'
%         plain: 'HIDETHEGOLDINTHETREESTUMP'
%
% See also polybius, adfgx, adfvgx, nihilist
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
ckey=double(upper(key)); ckey(ckey>90 | ckey<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73;
ckey(ckey==74)=73; 

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end
out.key=char(ckey);

% Polybius square generation from Key
% Using the key "PLAYFAIR EXAMPLE"
% Chars of the key must be choosen only once
% PLAYFIREXM
ckey=unique(ckey,'stable');
% then all the others into alphabetic order

%    1   2   3   4   5
% 1  P   L   A   Y   F
% 2  I   R   E   X   M
% 3  B   C   D   G   H
% 4  K   N   O   Q   S
% 5  T   U   V   W   Z

A=[65:1:73 75:1:90];
[~,locb]=ismember(ckey,A);
A(locb)=[];
PS=reshape([ckey A],[5,5])';
clear A locb ckey

switch direction
    case 1 %Encrypt
        % To encrypt a message, one would break the message into digrams
        % (groups of 2 letters) such that, for example, "HelloWorld"
        % becomes "HE LL OW OR LD". 
        tmp=[];
        while length(ctext)>1
            a=ctext(1); b=ctext(2);
            if a~=b %if digrams are by two different letters, i.e. HE, add both to tmp and erase from ctext;
                tmp=[tmp a b]; %#ok<*AGROW>
                ctext([1 2])=[];
            else %if digrams are by two equal letters, i.e. LL,
                %add the first to tmp and erase it from ctext; then append
                %an uncommon letter, such as "X" (ASCII=88), to complete
                %the final digram. If the letter is an "X", append a "Q"
                %(ASCII=81).  
                if a~=88
                    tmp=[tmp a 88];
                else
                    tmp=[tmp a 81];
                end
                ctext(1)=[];
            end
        end
        % Since encryption requires pairs of letters, messages with an odd
        % number of characters usually append an uncommon letter, such as
        % "X" (ASCII=88), to complete the final digram. If the last letter
        % is an "X", append a "Q" (ASCII=81).
        if length(ctext)==1
            if ctext==88
                tmp=[tmp ctext 81];
            else
                tmp=[tmp ctext 88];
            end
        end
        L=length(tmp)/2; %lenght of digrams vector
        ctext=reshape(tmp,2,L)'; %reshape tmp vector into Lx2 matrix
        clear a b tmp
    case -1 %decrypt
        L=length(text)/2; %lenght of digrams vector
        ctext=double(reshape(text,2,L)'); %reshape text vector into Lx2 matrix
end

tmp=zeros(L,2); %vector preallocation

switch direction
    case 1 %encrypt
        A=[2 3 4 5 1];
    case -1 %decrypt
        A=[5 1 2 3 4];
end

for I=1:L
    [R1,C1]=find(PS==ctext(I,1)); %find row and column of the 1st digram letter into the Polybius Square
    [R2,C2]=find(PS==ctext(I,2)); %find row and column of the 2nd digram letter into the Polybius Square
    if R1~=R2
        if C1~=C2
            %If the letters are not on the same row or column, replace them
            %with the letters on the same row respectively but at the other
            %pair of corners of the rectangle defined by the original pair.
            %The order is important – the first letter of the encrypted
            %pair is the one that lies on the same row as the first letter
            %of the plaintext pair. Pratically... switch columns!
            tmp(I,:)=[PS(R1,C2) PS(R2,C1)];
        else
            %If the letters appear on the same column of your table,
            %replace them with the letters immediately below respectively
            %(wrapping around to the top side of the column if a letter in
            %the original pair was on the bottom side of the column). THIS
            %IS THE MEANING OF THE "A" VECTOR (wrapping).
            tmp(I,:)=[PS(A(R1),C1) PS(A(R2),C1)];
        end
    else
        %If the letters appear on the same row of your table, replace them
        %with the letters to their immediate right respectively (wrapping
        %around to the left side of the row if a letter in the original
        %pair was on the right side of the row). THIS IS THE MEANING OF THE
        %"A" VECTOR (wrapping).   
        tmp(I,:)=[PS(R1,A(C1)) PS(R1,A(C2))];
    end
end
clear PS R1 R2 C1 C2 I ctext A

switch direction
    case 1 %encrypt
        %simply reshape the tmp array
        out.encrypted=char(reshape(tmp',1,L*2));
        clear tmp
    case -1 %decrypt
        %reshape the tmp array
        L=L*2;
        tmp=reshape(tmp',1,L);
        %Find all the "Q"
        Q=find(tmp==81); 
        q=[];
        if ~isempty(Q) %If there are some Q...
            for I=1:length(Q)
                if Q(I)==L && tmp(Q(I)-1)==88
                    %if "Q" is the last letter and "X" is the second last
                    %"Q" was added to pad. So, add them into erasing "q"
                    %array
                    q=[q Q(I)];
                elseif Q(I)>1 && tmp(Q(I)-1)==88 && tmp(Q(I)+1)==88
                    %if "Q" is not the first letter and the preceding and
                    %the following letters are "X", "Q" was added to
                    %divide digram. So, add this position into erasing "q" array.
                    q=[q Q(I)];
                end
            end
            clear I
            if ~isempty(q)
                %if there are "Q" that must be erased, erase them and
                %update tmp length.
                tmp(q)=[]; 
                L=length(tmp);
            end
        end
        clear Q q
        
        %Find all the "X"
        X=find(tmp==88); 
        x=[];
        if ~isempty(X) %If there are some X...
            for I=1:length(X)
                if X(I)>1 && X(I)<L
                    %If "X" is the first letter, surely it wasn't added;
                    %If "X" is the last letter, it is impossible to
                    %automatically establish if it was added to pad of it
                    %is a real "X". So, we will scan between 2 and end-1
                    if tmp(X(I)-1)==tmp(X(I)+1)
                        %if the preceding and the following letters are 
                        %equal, "X" was added to divide digram. 
                        %So, add this position into erasing "q" array.
                        x=[x X(I)];
                    end
                end
            end
            clear I
            if ~isempty(x) %if there are "X" that must be erased, erase them
                tmp(x)=[];
            end
        end
        clear X x
        out.plain=char(tmp);
        clear tmp
end