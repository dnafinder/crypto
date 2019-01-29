function out=checkerboard2(text,pskey,key1,key2,direction)
%CHECKERBOARD1 Cipher encoder/decoder
%This is another cypher that use a Polybius 5x5 square. In this case, the
%numeric coordinates of Polybius Cipher are changed using the 5 letters of
%key1 and key2; two 5 letters words for each key. Key A and Key B of each
%keyx must not share letters.
%
% Syntax: 	out=checkerboard1(text,pskey,key1,key2,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           pskey - It is the keyword to generate Polybius square
%           key1 - It is a 2x5 letters key for row coordinates
%           key2 - It is a 2x5 letters key for column coordinates
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.pskey = the used key to generate Polybius square
%           out.key1 = the used key1 for row coordinates
%           out.key2 = the used key2 for column coordinates
%           out.encrypted = the coded text
%
% Examples:
% 
% out=checkerboard2('Hide the gold into the tree stump','leprachaun',['black';'ghost'],['train';'ghoul'],1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%         pskey: 'LEPRACHAUN'
%          key1: [2×5 char]
%          key2: [2×5 char]
%     encrypted: 'HHOIOTGHCLLHBHOASRGTATOIHUSNCRCLLRGRCNGIBRGHCUSLHOCTBO'
%
% out=checkerboard2('HHOIOTGHCLLHBHOASRGTATOIHUSNCRCLLRGRCNGIBRGHCUSLHOCTBO','leprachaun',['black';'ghost'],['train';'ghoul'],-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'HHOIOTGHCLLHBHOASRGTATOIHUSNCRCLLRGRCNGIBRGHCUSLHOCTBO'
%         pskey: 'LEPRACHAUN'
%          key1: [2×5 char]
%          key2: [2×5 char]
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% See also adfgx, adfgvx, bifid, checkerboard1, foursquares, nihilist, playfair, polybius, threesquares, trifid, twosquares
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo-edta@poste.it
p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'pskey',@(x) ischar(x));
addRequired(p,'key1',@(x) ischar(x));
addRequired(p,'key2',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,pskey,key1,key2,direction);
clear p

assert(isequal(size(key1),[2 5]) && isequal(size(key2),[2 5]),'Key1 and Key2 must be 2x5 letters long')
key1=upper(key1);
key2=upper(key2);
assert(all(~ismember(key1(1,:),key1(2,:))),'key1 A and key1 B must not share letters')
assert(all(~ismember(key2(1,:),key2(2,:))),'key2 A and key2 B must not share letters')

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text)); ctext(ctext<65 | ctext>90)=[]; 
ckey=double(upper(pskey)); ckey(ckey>90 | ckey<65)=[]; 
% Convert J (ASCII code 74) into I (ASCII code 73)
ctext(ctext==74)=73; 
ckey(ckey==74)=73; 

switch direction
    case 1
        out.plain=char(ctext);
    case -1
        out.encrypted=char(ctext);
end
out.pskey=char(ckey);
out.key1=key1;
out.key2=key2;

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
PS=reshape([ckey A(~ismember(A,ckey))],[5,5])';
clear ckey A

switch direction
    case 1
        % Find the index of each characters into Polybius square
        [~,locb]=ismember(ctext,PS);
        clear PS ctext
        % transform index into subscripts
        [I,J]=ind2sub([5,5],locb);
        clear locb
        L=length(I);
        s1=binornd(1,0.5,L,2)+1;
        out.encrypted=reshape([key1(sub2ind([2,5],s1(:,1)',I));key2(sub2ind([2,5],s1(:,2)',J))],1,2*length(I));
        clear I J L s1
    case -1
        ctext=char(reshape(ctext',2,length(ctext)/2));
        [~,I]=ismember(ctext(1,:),key1); [~,I]=ind2sub([2,5],I);
        [~,J]=ismember(ctext(2,:),key2); [~,J]=ind2sub([2,5],J);
        clear ctext
        Idx=sub2ind([5,5],I,J);
        clear I J
        out.plain=char(PS(Idx));
        clear PS Idx
end