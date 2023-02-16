function out=chaocipher(text,direction,varargin)
% CHAOCIPHER Encoder/Decoder
% The Chaocipher is a cipher method invented by J. F. Byrne in 1918 and
% described in his 1953 autobiographical Silent Years. He believed
% Chaocipher was simple, yet unbreakable and he offered cash rewards for
% anyone who could solve it. In May 2010 the Byrne family donated all
% Chaocipher-related papers and artifacts to the National Cryptologic
% Museum in Ft. Meade, Maryland, USA. This led to the disclosure of the
% Chaocipher algorithm. 
% The Chaocipher system consists of two alphabets, with the "right"
% alphabet used for locating the plaintext letter while the other ("left")
% alphabet is used for reading the corresponding ciphertext letter. The
% underlying algorithm is related to the concept of dynamic substitution
% whereby the two alphabets are slightly modified after each input
% plaintext letter is enciphered. This leads to nonlinear and highly
% diffused alphabets as encryption progresses.
%
% Syntax: 	out=adfgx(text,direction,la,ra)
%
%     Input:
%           text - It is a characters array to encode or decode
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%           la - left alphabet: a scrambled 26 English standard alphabet. 
%           If it is empty and direction is 1, the software will generate it.
%           ra - right alphabet: a scrambled 26 English standard alphabet.
%           If it is empty and direction is 1, the software will generate it. 
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.key = the used key
%           out.la = the used left alphabet
%           out.ra = the used right alphabet
%           out.encrypted = the coded text
%
% Examples:
%
% la='HXUCZVAMDSLKPEFJRIGTWOBNYQ';
% ra='PTLNBQDEOYSFAVZKGJRIHWXUMC';
% out=chaocipher('Hide the gold into the tree stump',1,la,ra)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%            la: 'HXUCZVAMDSLKPEFJRIGTWOBNYQ'
%            ra: 'PTLNBQDEOYSFAVZKGJRIHWXUMC'
%     encrypted: 'WGZZNAXLHIBLVEIUIXYTLCTWSTT'
%
% la='HXUCZVAMDSLKPEFJRIGTWOBNYQ';
% ra='PTLNBQDEOYSFAVZKGJRIHWXUMC';
% out=chaocipher('WGZZNAXLHIBLVEIUIXYTLCTWSTT',-1,la,ra)
%
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'WGZZNAXLHIBLVEIUIXYTLCTWSTT'
%            la: 'HXUCZVAMDSLKPEFJRIGTWOBNYQ'
%            ra: 'PTLNBQDEOYSFAVZKGJRIHWXUMC'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
addOptional(p,'la',[], @(x) isempty(x) || (ischar(x) && length(x)==26));
addOptional(p,'ra',[], @(x) isempty(x) || (ischar(x) && length(x)==26));
parse(p,text,direction,varargin{:});
la=p.Results.la; ra=p.Results.ra; clear p

%if alphabets are empty, if direction is decrypt then exit, else create a permutated alphabet.
%if alphabets are not empty, check it they are a standard permutated english alphabet.
if isempty(la)
    assert(direction==1,'This algorithm cannot decode without a left alphabet')
    la=char(randperm(26)+64);
else
    la=double(upper(la)); la(la<65 | la>90)=[]; la=unique(la,'stable');
    assert(sum(ismember(la,65:1:90))==26,'Left alphabet must be a permutation of a standard alphabet of 26 letter')
    la=char(la);
end
if isempty(ra)
    assert(direction==1,'This algorithm cannot decode without a right alphabet')
    ra=char(randperm(26)+64);
else
    ra=double(upper(ra)); ra(ra<65 | ra>90)=[]; ra=unique(ra,'stable');
    assert(sum(ismember(ra,65:1:90))==26,'Right alphabet must be a permutation of a standard alphabet of 26 letter')
    ra=char(ra);
end

%ASCII CODES FOR [ABCDEFGHIJKLMNOPQRSTUVWXYZ]
text=double(upper(text)); 
text(text<65 | text>90)=[]; 
text=char(text);

switch direction
    case 1
        out.plain=text;
    case -1
        out.encrypted=text;
end
out.la=la; out.ra=ra;

L=length(text);
texttmp='';
for I=1:L
    switch direction 
        case 1 %encrypt
            %find the letter into the right alphabet and exchange it with
            %the letter in the same position into the left alphabet
            pos=find(ra==text(I));
            texttmp=strcat(texttmp,la(pos));
        case -1 %decrypt
            %find the letter into the leftalphabet and exchange it with
            %the letter in the same position into the right alphabet
            pos=find(la==text(I));
            texttmp=strcat(texttmp,ra(pos));
    end
    %Shift the entire left alphabet cyclically so the ciphertext letter
    %just enciphered is positioned at the position 1.
    tmp=circshift(la,-pos+1);
    %Extract the letter found at position 2 taking it out of the alphabet,
    %temporarily leaving an unfilled ‘hole’.  Shift all letters in
    %positions 2 up to, and including, the position 14, moving them one
    %position to the left. Insert the just-extracted letter into the
    %position 14.
    la=tmp([1 3:14 2 15:26]);
    %Shift the entire right alphabet cyclically so the plaintext letter
    %just enciphered is positioned at the position 1. Now shift the entire
    %alphabet one more position to the left (i.e., the leftmost letter
    %moves cyclically to the far right), moving a new letter into the
    %position 1.
    tmp=circshift(ra,-pos);
    %Extract the letter at position 3, taking it out of the alphabet,
    %temporarily leaving an unfilled ‘hole’. Shift all letters beginning
    %with 4 up to, and including, the position 14, moving them one position
    %to the left. Insert the just-extracted letter into the position 14.
    ra=tmp([1 2 4:14 3 15:26]);
end

switch direction
    case 1
        out.encrypted=texttmp;
    case -1
        out.plain=texttmp;
end