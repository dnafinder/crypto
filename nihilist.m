function out=nihilist(x,key1,key2,ms)
% NIHILIST SUBSTITUTION Cipher encoder/decoder
% In the history of cryptography, the Nihilist cipher is a manually
% operated symmetric encryption cipher, originally used by Russian
% Nihilists in the 1880s to organize terrorism against the tsarist regime.
% The term is sometimes extended to several improved algorithms used much
% later for communication by the First Chief Directorate with its spies. 
% First the encipherer constructs a Polybius square using a mixed alphabet.
% This is used to convert both the plaintext and a keyword to a series of
% two digit numbers. These numbers are then added together in the normal
% way to get the ciphertext, with the key numbers repeated as required.
% Because each symbol in both plaintext and key is used as a whole number
% without any fractionation, the basic Nihilist cipher is little more than
% a numerical version of the Vigenère cipher, with multiple-digit numbers
% being the enciphered symbols instead of letters. As such, it can be
% attacked by very similar methods. An additional weakness is that the use
% of normal addition (instead of modular addition) leaks further
% information.      
% 
% Syntax: 	out=nihilist(x,key1,key2,ms)
%
%     Input:
%           x - It can be a characters array or a numbers array. In first
%           case it will encoded; in the second case it will decoded. 
%           key1 - It is the keyword used to generate Polybius Square. If
%           ms parameter is equal to 5, all J will be transformed into I.
%           key2 - It is the keyword used to perform addition
%           ms - this parameter can assume only two values: 
%                   5 to use a 5x5 Polybius square (default)
%                   6 to use a 6x6 Polybius square
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.ms=the size of Polybius Square
%           out.key1 = the used key1
%           out.key2 = the used key2
%           out.encrypted = the coded text
%
% Examples:
% 
% out=nihilist('Hide the gold into the tree stump','leprachaun','ghosts and goblins',5)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%            ms: 5
%          key1: 'leprachaun'
%          key2: 'ghosts and goblins'
%     encrypted: [55 56 73 56 90 66 27 57 73 44 73 59 35 79 66 89 55 34 87 58 57 56 59 69 54 74 55]
% 
% out=nihilist([55 56 73 56 90 66 27 57 73 44 73 59 35 79 66 89 55 34 87 58 57 56 59 69 54 74 55],'leprachaun','ghosts and goblins',5)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: [55 56 73 56 90 66 27 57 73 44 73 59 35 79 66 89 55 34 87 58 57 56 59 69 54 74 55]
%            ms: 5
%          key1: 'leprachaun'
%          key2: 'ghosts and goblins'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, checkerboard2, foursquares, nihilist2, playfair, polybius, trifid, twosquares, vigenere
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it

%Input Checking        
assert(ischar(x) || all(isnumeric(x)))
assert(ischar(key1),'key1 must be a char vector')
assert(ischar(key2),'key2 must be a char vector')
assert(isempty(ms) || ms==5 || ms==6,'Polybius matrix must be 5x5 or 6x6')
if isempty(ms)
    ms=5;
end

if ischar(x) %encrypt
    out.plain=upper(x);
    % Set all letters in uppercase and convert into ASCII Code.
    text=double(out.plain);
    switch ms
        case 5
            % Erase all characters that are not into the range 65 - 90;
            text(text<65 | text>90)=[]; 
            % Convert J (ASCII code 74) into I (ASCII code 73)
            text(text==74)=73;
        case 6
            % ASCII codes for Uppercase letters ranges between 65 and 90;
            % ASCII codes for digits ranges between 48 and 57;
            % Erase all ASCII codes between 57 and 65; below 48 and above 90
            text(text>57 & text<65)=[]; 
            text(text<48 | text>90)=[];
    end
else %decrypt
    out.encrypted=x;
    text=x;
end
out.ms=ms;

switch ms
    case 5
        % Set all letters in uppercase and convert into ASCII Code.
        % Erase all characters that are not into the range 65 - 90 and
        % convert J (ASCII code 74) into I (ASCII code 73) for both keys
        ckey1=double(upper(key1)); ckey1(ckey1>90 | ckey1<65)=[]; ckey1(ckey1==74)=73;
        ckey2=double(upper(key2)); ckey2(ckey2>90 | ckey2<65)=[]; ckey2(ckey2==74)=73; 
    case 6
        % ASCII codes for Uppercase letters ranges between 65 and 90;
        % ASCII codes for digits ranges between 48 and 57;
        % Erase all ASCII codes between 57 and 65; below 48 and above 90
        ckey1=double(upper(key1)); ckey1(ckey1>57 & ckey1<65)=[]; ckey1(ckey1<48 | ckey1>90)=[]; 
        ckey2=double(upper(key2)); ckey2(ckey2>57 & ckey2<65)=[]; ckey2(ckey2<48 | ckey2>90)=[]; 
end
out.key1=key1;
out.key2=key2;

%Polybius square generation from Key1
switch ms
    case 5
        %A=ASCII CODES FOR [ABCDEFGHIKLMNOPQRSTUVWXYZ]
        A=[65:1:73 75:1:90];
    case 6
        %A=ASCII CODES FOR [ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789]
        A=[65:1:90 48:1:57];
end
% Using the key "PLAYFAIR EXAMPLE" AND A 5x5 Polybius Square
% Chars of the key must be choosen only once
% PLAYFIREXM
ckey1=unique(ckey1,'stable');
% then all the others into alphabetic order

%    1   2   3   4   5
% 1  P   L   A   Y   F
% 2  I   R   E   X   M
% 3  B   C   D   G   H
% 4  K   N   O   Q   S
% 5  T   U   V   W   Z
PS=reshape([ckey1 A(~ismember(A,ckey1))],[ms,ms])';
clear ckey1

%Key2 encoding
%key2='OCTOBER'
% Find the index of each key2 characters into Polybius square
[~,locb]=ismember(ckey2,PS);
% transform index into subscripts
[I,J]=ind2sub([ms,ms],locb);
% Combine subcripts
outkey2=I.*10+J;
%outkey2 =[43 32 51 43 31 23 22]
clear locb I J ckey2

%Key2 padding
%text is 25 characters long; key2 is 7 characters long
L=length(text);
%Repeat coded key2 25/7=4 times
RL=ceil(L/length(outkey2));
outkey3=repmat(outkey2,1,RL); 
%take the first 25 characters
out2=outkey3(1:L);
%out2 = [43 32 51 43 31 23 22 43 32 51 43 31 23 22 43 32 51 43 31 23 22 43 32 51 43]
clear RL L outkey*

if ischar(x) %encrypt
    % Find the index of each text characters into Polybius square
    [~,locb]=ismember(text,PS);
    % transform index into subscripts
    [I,J]=ind2sub([ms,ms],locb);
    % Combine subcripts
    out1=I.*10+J;
    %out1 = [33 14 42 13 25 21 51 23 13 51 51 35 23 54 21 42 51 23 22 11 13 12 13 32 23]
    clear locb I J text
    %sum out1 and out2
    %out1 = [33 14 42 13 25 21 51 23 13 51  51 35 23 54 21 42 51  23 22 11 13 12 13 32 23]
    %out2 = [43 32 51 43 31 23 22 43 32 51  43 31 23 22 43 32 51  43 31 23 22 43 32 51 43]
    %out3 = [76 46 93 56 56 44 73 66 45 102 94 66 46 76 64 74 102 66 53 34 35 55 45 83 66]
    %
    % note that if a ciphertext number is greater than 100 then it is a
    % certainty that both the plaintext and key came from the fifth row of
    % the table.   
    out.encrypted=out1+out2;
else %decrypt
    %subtract out2 from x
    out1=x-out2;
    %x    = [76 46 93 56 56 44 73 66 45 102 94 66 46 76 64 74 102 66 53 34 35 55 45 83 66]
    %out2 = [43 32 51 43 31 23 22 43 32  51 43 31 23 22 43 32  51 43 31 23 22 43 32 51 43]
    %out1 = [33 14 42 13 25 21 51 23 13  51 51 35 23 54 21 42  51 23 22 11 13 12 13 32 23]
    % From each two-digits number:
    % the first digit is the row
    I=fix(out1./10);
    % the second is the column
    J=out1-I.*10;
    % trasform subscripts into index
    Ind=sub2ind([ms,ms],I,J); clear I J
    % take ASCII codes from Polybius square and transform them into letters
    out.plain=char(PS(Ind));
end