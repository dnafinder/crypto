function out=baconian(text,direction)
% BACONIAN Cipher encoder/decoder
%Bacon's encryption uses a substitution alphabet based on 2 letters
%(sometimes called biliteral or baconian), often A and B, replacing the
%letters of the alphabet. The ciphered message is a binary code (with 2
%distinct characters), and maybe spaces every 5 characters. Francis Bacon
%first described the Bacon alphabet around 1605. If you encrypt the same
%messagge twice, you will obtain two different coded text.
%
% Syntax: 	out=baconian(text,direction)
%
%     Input:
%           text - It is a characters array to encode or decode
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text
%           out.encrypted = the coded text
%
% Examples:
%
% out=baconian('Hide the gold into the tree stump',1)
% 
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%     encrypted: 'CBNVQGUDKIAGFUXAHWMKWMAUVDCUYVHGTBLKCYOAEUWQCDYGWQBHCTZDTIKBHRXJNVMAUOBYOQAOGEZNIDWSQHKTFBXKDTYSLGMRHLODGCFSIETDKWENCBTYXERBLLZSIAEWUSZ'
% 
% out=baconian('CBNVQGUDKIAGFUXAHWMKWMAUVDCUYVHGTBLKCYOAEUWQCDYGWQBHCTZDTIKBHRXJNVMAUOBYOQAOGEZNIDWSQHKTFBXKDTYSLGMRHLODGCFSIETDKWENCBTYXERBLLZSIAEWUSZ',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'CBNVQGUDKIAGFUXAHWMKWMAUVDCUYVHGTBLKCYOAEUWQCDYGWQBHCTZDTIKBHRXJNVMAUOBYOQAOGEZNIDWSQHKTFBXKDTYSLGMRHLODGCFSIETDKWENCBTYXERBLLZSIAEWUSZ'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'},{'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,direction);
clear p

% ASCII codes for Uppercase letters ranges between 65 and 90;
ctext=double(upper(text));
ctext(ctext<65 | ctext>90)=[];
%scale each number between 0 and 25
ctext=ctext-65;
%split the alphabeth in two halves
array0=0:1:12;
array1=13:1:25; 

switch direction
    case 1 %if you are encrypting...
        out.plain=text; out.encrypted='';
        %convert into 5 bits binary
        bintext=dec2bin(ctext,5);
        clear ctext
        for I=1:length(bintext)
            z=zeros(1,5); %preallocation
            x=bintext(I,:); %take the i-esim byte
            K=strfind(x,'0'); %index of 0 bits
            z(K)=randsample(array0,length(K)); %choose random letters from the first array  
            K=strfind(x,'1');%index of 1 bits
            z(K)=randsample(array1,length(K)); %choose random letters from the second array
            out.encrypted=strcat(out.encrypted,char(z+65)); %convert into ascii code
        end
    case -1 %if you are decrypting...
        out.encrypted=text; out.plain='';
        x=reshape(ctext,5,length(text)/5)'; %reshape into Nx5 matrix
        z=zeros(size(x)); %preallocation
        z(x>12)=1; %index of 1 bits;
        clear x
        for I=1:length(z)
            %convert each byte into ascii code
            out.plain=strcat(out.plain,char(bin2dec(num2str(z(I,:)))+65));
        end
end
end
